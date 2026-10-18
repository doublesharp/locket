//! Atomic composition of store operations used by validated imports.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use crate::{Store, StoreError};

impl Store {
    /// Runs composed writes atomically, including nested lifecycle operations.
    ///
    /// A failed operation rolls back every write made by the closure. The
    /// savepoint also composes with an enclosing store transaction.
    ///
    /// # Errors
    ///
    /// Returns the operation error or a storage error if savepoint management fails.
    pub fn with_atomic_write<T, E>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<StoreError>,
    {
        self.connection.execute_batch("SAVEPOINT locket_atomic_write").map_err(StoreError::from)?;
        match catch_unwind(AssertUnwindSafe(|| operation(self))) {
            Ok(Ok(value)) => {
                if let Err(error) = self.connection.execute_batch("RELEASE locket_atomic_write") {
                    let _ = self.connection.execute_batch(
                        "ROLLBACK TO locket_atomic_write; RELEASE locket_atomic_write",
                    );
                    return Err(StoreError::from(error).into());
                }
                Ok(value)
            }
            Ok(Err(error)) => {
                self.connection
                    .execute_batch("ROLLBACK TO locket_atomic_write; RELEASE locket_atomic_write")
                    .map_err(StoreError::from)?;
                Err(error)
            }
            Err(payload) => {
                let _ = self
                    .connection
                    .execute_batch("ROLLBACK TO locket_atomic_write; RELEASE locket_atomic_write");
                resume_unwind(payload)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{StoreError, tests::*};

    #[test]
    fn atomic_write_rolls_back_prior_secret_when_a_later_write_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = open_initialized_store()?;
        insert_project_profile(&fixture.store)?;
        let result = fixture.store.with_atomic_write::<_, StoreError>(|store| {
            store.create_active_secret(
                &test_secret(),
                &test_secret_version(),
                &test_secret_blob(),
                &test_secret_fingerprint(),
            )?;
            store.create_active_secret(
                &test_secret(),
                &test_secret_version(),
                &test_secret_blob(),
                &test_secret_fingerprint(),
            )
        });
        assert!(result.is_err());
        assert!(
            fixture
                .store
                .get_secret_by_source("lk_proj_test", "lk_prof_test", "DATABASE_URL", "user-local")?
                .is_none()
        );
        assert!(fixture.store.connection().is_autocommit());
        Ok(())
    }

    #[test]
    fn atomic_write_commits_composed_secret_lifecycle_operations()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = open_initialized_store()?;
        insert_project_profile(&fixture.store)?;
        fixture.store.with_atomic_write::<_, StoreError>(|store| {
            store.create_active_secret(
                &test_secret(),
                &test_secret_version(),
                &test_secret_blob(),
                &test_secret_fingerprint(),
            )
        })?;
        assert!(
            fixture
                .store
                .get_secret_by_source("lk_proj_test", "lk_prof_test", "DATABASE_URL", "user-local")?
                .is_some()
        );
        assert!(fixture.store.connection().is_autocommit());
        Ok(())
    }
}
