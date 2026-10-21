const child_process = require('child_process');

function run(user, db) {
  // ruleid: javascript.child-process-dynamic
  child_process.exec('ls ' + user);
  // ok: javascript.child-process-dynamic
  child_process.execFile('ls', [user]);
  // ok: javascript.child-process-dynamic
  child_process.exec('ls -l');
  // ruleid: javascript.eval-dynamic
  eval(user);
  // ok: javascript.eval-dynamic
  eval('1 + 1');
  // ruleid: javascript.sql-built-from-strings
  db.query('SELECT * FROM notes WHERE id = ' + user);
  // ruleid: javascript.sql-built-from-strings
  db.query(`SELECT * FROM notes WHERE id = ${user}`);
  // ok: javascript.sql-built-from-strings
  db.query('SELECT * FROM notes WHERE id = ?', [user]);
}
