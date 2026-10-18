import { mkdtemp, mkdir, writeFile, chmod, rm, access, symlink } from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveProjectContext } from './projectContext';

test('metadata resolver uses fixed CLI argv, actual nested IDs, and trusted absolute PATH executable', async () => {
  const fixture = await makeFixture();
  try {
    const project = await resolveProjectContext({ trusted: true, cwd: fixture.nested, workspaceRoots: [fixture.workspace], pathEnvironment: fixture.bin });
    assert.equal(project.root, fixture.nested);
    assert.equal(project.projectId, 'lk_proj_actual');
    assert.equal(project.defaultProfileId, 'lk_prof_actual');
    assert.equal(project.profileName, 'staging');
    assert.equal(project.storePath, path.join(fixture.directory, 'store.db'));
    assert.equal(project.cliPath, path.join(fixture.bin, 'locket'));
  } finally { await fixture.cleanup(); }
});

test('metadata resolution refuses untrusted workspaces before executing a CLI', async () => {
  await assert.rejects(resolveProjectContext({ trusted: false, cwd: '/workspace', workspaceRoots: ['/workspace'], pathEnvironment: '/usr/bin' }), /trusted/iu);
});

test('CLI discovery skips relative PATH entries and executables within workspace roots including symlinks', async () => {
  const fixture = await makeFixture();
  try {
    const marker = path.join(fixture.directory, 'evil-ran');
    const evil = path.join(fixture.workspace, 'locket');
    await writeFile(evil, `#!${process.execPath}\nrequire('fs').writeFileSync(${JSON.stringify(marker)},'bad');\n`);
    await chmod(evil, 0o755);
    const linked = path.join(fixture.directory, 'linked-bin');
    await mkdir(linked);
    await symlink(evil, path.join(linked, 'locket'));
    const project = await resolveProjectContext({ trusted: true, cwd: fixture.nested, workspaceRoots: [fixture.workspace], pathEnvironment: ['.', 'node_modules/.bin', fixture.workspace, linked, fixture.bin].join(path.delimiter) });
    assert.equal(project.projectId, 'lk_proj_actual');
    await assert.rejects(access(marker));
  } finally { await fixture.cleanup(); }
});

test('metadata resolver rejects malformed or unrelated-root metadata without invented IDs', async () => {
  const fixture = await makeFixture();
  try {
    await writeFile(path.join(fixture.bin,'locket'), `#!${process.execPath}\nprocess.stdout.write(JSON.stringify({root:'/elsewhere',project_id:'lk_proj_bad'}));\n`);
    await assert.rejects(resolveProjectContext({ trusted: true, cwd: fixture.nested, workspaceRoots: [fixture.workspace], pathEnvironment: fixture.bin }), /metadata/iu);
  } finally { await fixture.cleanup(); }
});

async function makeFixture(): Promise<{ directory:string;workspace:string;nested:string;bin:string;cleanup:()=>Promise<void> }> {
  const directory = await mkdtemp(path.join(os.tmpdir(),'locket-editor-context-'));
  const workspace=path.join(directory,'workspace');
  const nested=path.join(workspace,'nested');
  const bin=path.join(directory,'bin');
  await mkdir(nested,{recursive:true}); await mkdir(bin);
  const metadata={root:nested,project_id:'lk_proj_actual',project_name:'actual project',profile_id:'lk_prof_actual',profile_name:'staging',store_path:path.join(directory,'store.db')};
  await writeFile(path.join(bin,'locket'),`#!${process.execPath}\nif(JSON.stringify(process.argv.slice(2))!==JSON.stringify(['context','--json']))process.exit(2);if(process.cwd()!==${JSON.stringify(nested)})process.exit(3);process.stdout.write(${JSON.stringify(JSON.stringify(metadata))});\n`);
  await chmod(path.join(bin,'locket'),0o755);
  return {directory,workspace,nested,bin,cleanup:()=>rm(directory,{recursive:true,force:true})};
}

test('oversized CLI metadata fails safely without echoing process output', async()=>{
  const fixture=await makeFixture();
  try{
    await writeFile(path.join(fixture.bin,'locket'),`#!${process.execPath}\nprocess.stdout.write('private-output'.repeat(10000));\n`);
    await assert.rejects(resolveProjectContext({trusted:true,cwd:fixture.nested,workspaceRoots:[fixture.workspace],pathEnvironment:fixture.bin}),(error:unknown)=>error instanceof Error && !error.message.includes('private-output') && error.message.includes('could not resolve'));
  }finally{await fixture.cleanup();}
});

test('symlinked workspace PATH directories are excluded even when their executable points outside the workspace',async()=>{
  const fixture=await makeFixture();
  try{
    const alias=path.join(fixture.directory,'workspace-link');
    await symlink(fixture.workspace,alias);
    const localBin=path.join(fixture.workspace,'bin');
    await mkdir(localBin);
    const external=path.join(fixture.directory,'external-unsafe');
    const marker=path.join(fixture.directory,'unsafe-ran');
    await writeFile(external,`#!${process.execPath}\nrequire('fs').writeFileSync(${JSON.stringify(marker)},'bad');process.stdout.write('{}');\n`);
    await chmod(external,0o755);
    await symlink(external,path.join(localBin,'locket'));
    const project=await resolveProjectContext({trusted:true,cwd:path.join(alias,'nested'),workspaceRoots:[alias],pathEnvironment:[path.join(alias,'bin'),fixture.bin].join(path.delimiter)});
    assert.equal(project.projectId,'lk_proj_actual');
    await assert.rejects(access(marker));
  }finally{await fixture.cleanup();}
});

test('valid workspace metadata resolves when an unrelated multiroot folder is missing', async () => {
  const fixture = await makeFixture();
  try {
    const missing = path.join(fixture.directory, 'disconnected-workspace');
    const project = await resolveProjectContext({
      trusted: true,
      cwd: fixture.nested,
      workspaceRoots: [fixture.workspace, missing],
      pathEnvironment: [path.join(missing, 'bin'), fixture.bin].join(path.delimiter),
    });
    assert.equal(project.projectId, 'lk_proj_actual');
    assert.equal(project.defaultProfileId, 'lk_prof_actual');
  } finally {
    await fixture.cleanup();
  }
});
