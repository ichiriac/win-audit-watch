const evtx = require('evtx-listener');
const watch = require('node-watch');
const fs = require('fs');
// the audit instance
var audit;

class Listener {

  /**
   * Initialize a listener
   * @param {*} path 
   */
  constructor(path) {
    // the path filter
    this.path = path;

    // the audit instance
    if (!audit) {
      audit = new evtx('c:\\Windows\\System32\\Winevt\\Logs\\Security.evtx');
      // file write access
      audit.eventId(4663);
      // file delete access
      audit.eventId(4659);
    }
    
    this.watch = watch(path, {
      recursive: true
    }, this.fsEvent.bind(this));

    // listener
    audit.onChange(this.auditEvent.bind(this));

    // pending data
    this._nodes = {};
    this._ignore = {};
    this._pending = {};
    this._flush = {};
    this._cb = [];
    this.scanFolder(path);
  }

  /**
   * Stops the audit
   */
  stop() {
    this._cb = [];
    this.watch.close();
    if (audit) {
      audit.stop();
      audit = null;
    }
  }

  /**
   * Scan of files
   * @param {*} path 
   */
  scanFolder(path) {
    fs.readdir(path, {withFileTypes: true}, (err, files) => {
      if (err) {
        return console.log('Path ' + path, err);
      }
      files.forEach(file => {
        let filename = path + '\\' + file.name;
        fs.lstat(filename, (err, stat) => {
          if (err) {
            return console.log('File ' + filename, err);
          }
          if (stat.ino) {
            this._nodes[stat.ino] = filename;
          } else {
            console.log('No inode for ' + filename);
          }
          if (file.isDirectory()) {
            this.scanFolder(filename);
          }
        });
      });
    });
  }

  /**
   * Intercept a file
   * @param {*} evt 
   */
  auditEvent(evt) {
    let data = evt.data.details;
    //console.log(evt.data.EventId + ' - ' + data.ObjectName + ' : ' + data.AccessMask);
    if (!data) return;
    let filename = data.ObjectName.toLowerCase();
    if (filename.substring(0, this.path.length) !== this.path.toLowerCase()) {
      // the file path is not checked
      return;
    }
    // checking changes
    if (evt.data.EventId == 4663) {
      if (data.AccessMask == 0x2) {
        // change made on a file
        if (this.hasFile(filename)) {
          this.flush(filename, data.AccountDomain + '\\' + data.AccountName);
        }
      } else if (data.AccessMask === 0x10000) {
        // delete action on file
        this.flush(filename, data.AccountDomain + '\\' + data.AccountName);
      } else {
        // access on the file
        if (this._flush.hasOwnProperty(filename)) {
          if (!this._flush[filename].author) {
            this.flush(filename, data.AccountDomain + '\\' + data.AccountName);
          }
        } else if (this._pending.hasOwnProperty(filename)) {
          if (!this._pending[filename].author) {
            this.flush(filename, data.AccountDomain + '\\' + data.AccountName);
          }
        }
      }
    } else if (evt.data.EventId == 4659) {
      // remote delete a file
      this.flush(filename, data.AccountDomain + '\\' + data.AccountName);
    }
  }

  /**
   * Flush changes
   * @param {*} filename 
   * @param {*} account 
   */
  flush(filename, account) {
    if (this._ignore.hasOwnProperty(filename)) {
      delete this._ignore[filename];
      return;
    }
    if (this._pending.hasOwnProperty(filename)) {
      this._flush[filename] = this._pending[filename];
      if (account) {
        this._flush[filename].author = account;
      }
      delete this._pending[filename];
    } else if (this._flush.hasOwnProperty(filename)) {
      if (account) {
        this._flush[filename].author = account;
      }
    } else {
      console.warn('Event not detected for ' + filename + ' used by ' + account);
    }
    this._trigger();
  }

  /**
   * Triggers the change events
   * @param {*} force 
   */
  _trigger(force) {
    if (this._pTrigger) {
      clearTimeout(this._pTrigger);
    }
    if (!force) {
      this._pTrigger = setTimeout(this._trigger.bind(this, true), 1);
      return;
    }
    let events = this._flush;
    this._flush = {};
    for(let path in events) {
      try {
        this._cb.forEach(function(cb) {
          cb(path, events[path]);
        });  
      } catch(e) {
        console.error(e);
      }
    }
    this._checkTimeout();
  }

  hasFile(filename) {
    filename = filename.toLowerCase();
    return this._pending.hasOwnProperty(filename) || this._flush.hasOwnProperty(filename);
  }

  /**
   * Checking for timeouts
   */
  _checkTimeout(force) {
    if (this._pTimeout) {
      clearTimeout(this._pTimeout);
    }
    if (!force) {
      this._pTimeout = setTimeout(this._checkTimeout.bind(this, true), 30000);
      return;
    }
    let now = new Date();
    for(let path in this._pending) {
      let evt = this._pending[path];
      if (now - evt.when > 300 * 1000) {
        console.error('5 minutes tiemout on ' + path, evt);
        this.flush(path, null);
      }
    }
    this._checkTimeout();
  }

  /**
   * Intercept a change
   * @param {*} evt 
   */
  fsEvent(evt, name) {
    let filename = name.toLowerCase();
    if (!this._pending.hasOwnProperty(filename)) {
      this._pending[filename] = new Event(name, evt);
    } else {
      this._pending[filename].when = new Date();
      this._pending[filename].action = evt;
    }
    let file = this._pending[filename];
    if (file.uid) {
      if (!this._nodes.hasOwnProperty(file.uid)) {
        if (file.action === 'update') {
          file.set('create');
        } else {
          file.set('update');
        }
      } else {
        let old = this._nodes[file.uid];
        let oldKey = old.toLowerCase();
        if (oldKey !== filename) {
          if (this._pending.hasOwnProperty(oldKey)) {
            let oldEvt = this._pending[oldKey];
            file.isCreated = oldEvt.isCreated;
            file.isUpdated = oldEvt.isUpdated;
            if (oldEvt.from) {
              file.from = oldEvt.from;
            } else {
              file.from = old;
            }
            if (oldEvt.author) {
              file.author = oldEvt.author;
            }
            this._ignore[old] = new Date();
            delete this._pending[oldKey];
          } else {
            // delete already flushed
            console.warn('[RENAME:'+evt+'] File ' + name + ' => ' + old + ' already flushed as delete ('+file.uid+')');
          }
          file.set('rename');
        } else {
          file.set(file.action);
        }
      }
      this._nodes[file.uid] = name;
    } else {
      file.set(file.action);
    }
    // console.log('%s is %s.', name, evt);
  }

  /**
   * Listen on changes
   * @param {*} cb 
   */
  onChange(cb) {
    this._cb.push(cb);
    return this;
  }
}

/**
 * A change event
 */
class Event {
  constructor(name, action) {
    if (action !== 'remove') {
      let stat = fs.lstatSync(name);
      this.uid = stat.ino;
    } else {
      this.uid = null;
    }
    
    this.filename = name;
    this.when = new Date();
    this.author = null;
    this.isCreated = false;
    this.isDeleted = false;
    this.isUpdated = false;
    this.isRenamed = false;
    this.set(action);
  }
  set(action) {
    this.action = action;
    switch(action) {
      case 'create':
        this.isUpdated = false;
        this.isCreated = true;
        break;
      case 'update':
        this.isUpdated = true;
        break;    
      case 'remove':
        this.isDeleted = true;
        break;
      case 'rename':
        this.isRenamed = true;
        break;
    }
  }
}

module.exports = Listener;