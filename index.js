const express = require('express')
const redis = require('redis')
const upload = require('multer')()
const bodyParser = require('body-parser')
const session = require('express-session')
const uuid = require('uuid/v4')
const async = require('async')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const fs = require('fs')

const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy

const RedisStore = require('connect-redis')(session)
const redisClient = redis.createClient()

const usernameRegex = /^[\w-]+$/i
const id0Regex = /[\da-f]{32}/i
const fcRe = /\d\d\d\d-\d\d\d\d-\d\d\d\d/

const app = express()
app.set('view engine', 'pug')
app.set('trust proxy', 1)
app.use(bodyParser.urlencoded({
  extended: false
}))
app.use(session({
  store: new RedisStore({
    host: '127.0.0.1',
    port: 6379,
    db: 1 // session db, data is in db 0 (default)
  }),
  secret: process.env.SESSION_SECRET || 'insecure',
  resave: false,
  saveUninitialized: true,
  cookie: {
    // secure: true,
  }
}))
app.use(require('express-flash')())
app.use('/static', express.static('static'))
app.use(passport.initialize())
app.use(passport.session())

passport.use(new LocalStrategy((username, password, done) => {
  redisClient.exists(`users:${username}`, (err, reply) => {
    if (err) {
      return done(null, false, {
        message: 'Redis error. Please try again and report this issue if you see it again.'
      })
    }
    if (reply) {
      redisClient.hget(`users:${username}`, 'password', (err, reply) => {
        if (err) {
          return done(null, false, {
            message: 'Redis error. Please try again and report this issue if you see it again.'
          })
        }
        bcrypt.compare(password, reply, (err, match) => {
          if (err) {
            return done(null, false, {
              message: 'Bcrypt error. Please try again and report this issue if you see it again.'
            })
          }
          if (match) {
            return done(null, username)
          } else {
            return done(null, false, {
              message: 'Incorrect password.'
            })
          }
        })
      })
    } else {
      return done(null, false, {
        message: 'That user does not exist.'
      })
    }
  })
}))

passport.serializeUser((user, done) => {
  done(null, user)
})

passport.deserializeUser((id, done) => {
  done(null, id)
})

function enforceLogin (req, res, next) {
  if (req.user) {
    next()
  } else {
    req.flash('error', 'You must be logged in to view this page.')
    res.redirect('/login')
  }
}

// thank u so much to https://github.com/zaksabeast/3dsFriendCodeValidator/blob/master/index.html i've spent hours on this
function padStringLeft (str, paddingValue) {
  return String(paddingValue + str).slice(-paddingValue.length)
}

function verifyFc (fc) {
  let fcParts = padStringLeft(parseInt(fc.replace(/-/g, ''), 10).toString(16), '0000000000').match(/.{1,2}/g)
  let fcHex = padStringLeft(fcParts[4] + fcParts[3] + fcParts[2] + fcParts[1], '00000000')
  let shaObj = crypto.createHash('sha1')
  shaObj.update(fcHex, 'hex')
  var idChecksum = padStringLeft((parseInt(shaObj.digest('hex').slice(0, 2), 16) >> 1).toString(16), '00')

  return (fcParts[0] === idChecksum)
}

app.get('/', (req, res) => {
  if (!req.user) {
    res.render('index')
  } else {
    res.redirect('/home')
  }
})

app.get('/help', (req, res) => {
  res.render('help', {user: req.user})
})

app.get('/home', enforceLogin, (req, res) => {
  let array = []
  redisClient.smembers(`devices:${req.user}`, (err, deviceids) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect('/')
    }
    async.forEach(deviceids, (deviceid, callback) => {
      redisClient.hgetall(`device:${deviceid}`, (err, device) => {
        if (err) {
          req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
          return res.redirect('/')
        }
        device.id = deviceid
        array.push(device)
        callback()
      })
    }, err => {
      if (err) {
        req.flash('error', 'Looping error. Please try again and report this issue if you see it again.')
        return res.redirect('/')
      }
      res.render('home', {
        devices: array,
        user: req.user
      })
    })
  })
})

app.get('/add', enforceLogin, (req, res) => {
  const deviceid = uuid()
  redisClient.hmset(`device:${deviceid}`, {
    name: 'New Device',
    owner: req.user
  }, (err, result) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect('/home')
    }
    redisClient.sadd(`devices:${req.user}`, deviceid, (err, result) => {
      if (err) {
        req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
        return res.redirect('/home')
      }
      res.redirect(`/device/${deviceid}/edit`)
    })
  })
})

app.get('/device/:deviceid/edit', enforceLogin, (req, res) => {
  redisClient.hgetall(`device:${req.params.deviceid}`, (err, device) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect('/home')
    }
    if (!device) {
      req.flash('error', "This device doesn't exist.")
      return res.redirect('/home')
    }
    if (device.owner !== req.user) {
      req.flash('error', "You can't edit other people's devices.")
      return res.redirect(`/home`)
    }
    device.id = req.params.deviceid
    res.render('edit', {
      device: device,
      user: req.user
    })
  })
})

app.post('/device/:deviceid/edit', enforceLogin, upload.fields([{
  name: 'p1',
  maxCount: 1
}]), (req, res) => {
  if (!req.body.name) {
    req.flash('error', 'You must specify a name.')
    return res.redirect(`/device/${req.params.deviceid}/edit`)
  }
  let device = {
    name: req.body.name
  }
  redisClient.hgetall(`device:${req.params.deviceid}`, (err, oldDevice) => {
    if (err) {
      req.flash('error', 'Redis error 1. Please try again and report this issue if you see it again.')
      return res.redirect(`/device/${req.params.deviceid}/edit`)
    }
    if (!device) {
      req.flash('error', "This device doesn't exist.")
      return res.redirect('/home')
    }
    if (oldDevice.owner !== req.user) {
      req.flash('error', "You can't edit other people's devices.")
      return res.redirect(`/home`)
    }
    if (!Object.keys(req.files).length && !oldDevice.p1) {
      if (!req.body.id0 || !req.body.friendCode) {
        req.flash('error', 'You must specify id0 and a friend code.')
        return res.redirect(`/device/${req.params.deviceid}/edit`)
      } else {
        device.id0 = req.body.id0.toLowerCase()
        if (!fcRe.test(req.body.friendCode) || !verifyFc(req.body.friendCode)) {
          req.flash('error', 'You must specify a valid friend code.')
          return res.redirect(`/device/${req.params.deviceid}/edit`)
        }
        if (!id0Regex.test(req.body.id0)) {
          req.flash('error', 'You must specify a valid id0.')
          return res.redirect(`/device/${req.params.deviceid}/edit`)
        }
        device.friendCode = req.body.friendCode
        device.autoMovable = req.body.autoMovable || false
        redisClient.sadd('p1NeededDevices', req.params.deviceid, (err, result) => {
          if (err) {
            req.flash('error', 'Redis error 2. Please try again and report this issue if you see it again.')
            return res.redirect(`/device/${req.params.deviceid}/edit`)
          }
          redisClient.hmset(`device:${req.params.deviceid}`, device, (err, result) => {
            if (err) {
              req.flash('error', 'Redis error 3. Please try again and report this issue if you see it again.')
              return res.redirect(`/device/${req.params.deviceid}/edit`)
            }
            req.flash('success', 'Successfully added/edited device!')
            return res.redirect(`/home`)
          })
        })
      }
    } else if (!oldDevice.p1) {
      if (req.files.p1[0].size !== 4096) {
        req.flash('error', 'File is not a valid movable_part1.')
        return res.redirect(`/device/${req.params.deviceid}/edit`)
      }
      device.id0 = req.files.p1[0].buffer.slice(0x10, 0x30).toString('utf8')
      if (req.files.p1[0].buffer.readUIntBE(0, 4) === 0) {
        req.flash('error', 'Your movable_part1 appears to be blank. Did you dump this file yourself? If not, then don\'t specify a file and enter your friend code and id0 instead.')
        return res.redirect(`/work/part1/${req.params.deviceid}/edit`)
      }
      if (device.id0 === '\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000') {
        if (!req.body.id0) {
          req.flash('error', 'You need to specify ID0 or embed it into your movable_part1.sed.')
        } else {
          device.id0 = req.body.id0
        }
      }
      if (!id0Regex.test(device.id0)) {
        req.flash('error', 'Your ID0 or movable_part1 is invalid.')
        return res.redirect(`/work/part1/${req.params.deviceid}/edit`)
      }
      device.p1 = true
      req.files.p1[0].buffer.write(device.id0.toLowerCase(), 0x10, 0x40)
      fs.writeFile(`static/ugc/part1/${req.params.deviceid}_part1.sed`, req.files.p1[0].buffer, (err) => {
        if (err) {
          req.flash('error', 'File upload error. Please try again and report this issue if you see it again.')
          return res.redirect(`/device/${req.params.deviceid}/edit`)
        }
        redisClient.sadd('movableNeededDevices', req.params.deviceid, (err, result) => {
          if (err) {
            req.flash('error', 'Redis error 4. Please try again and report this issue if you see it again.')
            return res.redirect(`/device/${req.params.deviceid}/edit`)
          }
          redisClient.hmset(`device:${req.params.deviceid}`, device, (err, result) => {
            if (err) {
              req.flash('error', 'Redis error 5. Please try again and report this issue if you see it again.')
              return res.redirect(`/device/${req.params.deviceid}/edit`)
            }
            req.flash('success', 'Successfully added/edited device!')
            return res.redirect(`/home`)
          })
        })
      })
    } else if (oldDevice.p1) {
      redisClient.sadd('movableNeededDevices', req.params.deviceid, (err, result) => {
        if (err) {
          req.flash('error', 'Redis error 6. Please try again and report this issue if you see it again.')
          return res.redirect(`/device/${req.params.deviceid}/edit`)
        }
        req.flash('success', 'Successfully submitted device!')
        return res.redirect(`/home`)
      })
    }
  })
})

// this is broken out so it can also be used in deleteaccount

function deleteDevice (user, deviceid) {
  redisClient.hgetall(`device:${deviceid}`, (err, device) => {
    if (err || !device) {
      return {'error': 'Redis error. Please try again and report this issue if you see it again.'}
    }
    if (device.owner !== user) {
      return {'error': "You can't delete other people's devices."}
    }
    redisClient.del(`device:${deviceid}`, (err, result) => {
      if (err) {
        return {'error': 'Redis error. Please try again and report this issue if you see it again.'}
      }
      redisClient.srem(`devices:${user}`, deviceid, (err, result) => {
        if (err) {
          return {'error': 'Redis error. Please try again and report this issue if you see it again.'}
        }
        redisClient.srem(`p1NeededDevices`, deviceid, (err, result) => {
          if (err) {
            return {'error': 'Redis error. Please try again and report this issue if you see it again.'}
          }
          redisClient.srem(`movableNeededDevices`, deviceid, (err, result) => {
            if (err) {
              return {'error': 'Redis error. Please try again and report this issue if you see it again.'}
            }
            redisClient.srem(`workingDevices`, deviceid, (err, result) => {
              if (err) {
                return {'error': 'Redis error. Please try again and report this issue if you see it again.'}
              }
              if (device.worker) {
                redisClient.srem(`workingDevices:${device.worker}`, deviceid, (err, result) => {
                  if (err) {
                    return {'error': 'Redis error. Please try again and report this issue if you see it again.'}
                  }
                  fs.unlink(`static/ugc/movable/${deviceid}_movable.sed`, (err) => {
                    if (err && err !== 'ENOENT') { // file not found
                      fs.unlink(`static/ugc/part1/${deviceid}_part1.sed`, (err) => {
                        if (err && err !== 'ENOENT') { // file not found
                          // success, no return
                        }
                      })
                    }
                  })
                })
              } else {
                fs.unlink(`static/ugc/movable/${deviceid}_movable.sed`, (err) => {
                  if (err && err !== 'ENOENT') { // file not found
                    fs.unlink(`static/ugc/part1/${deviceid}_part1.sed`, (err) => {
                      if (err && err !== 'ENOENT') { // file not found
                        // success, no return
                      }
                    })
                  }
                })
              }
            })
          })
        })
      })
    })
  })
}

app.get('/device/:deviceid/delete', enforceLogin, (req, res) => {
  let err = deleteDevice(req.user, req.params.deviceid)
  if (err) {
    for (let type in err) {
      req.flash(type, err[type])
    }
  } else {
    req.flash('success', 'Device deleted successfully!')
  }
  res.redirect('/home')
})

app.get('/deleteaccount', enforceLogin, (req, res) => {
  redisClient.smembers(`devices:${req.user}`, (err, deviceids) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect('/')
    }
    async.forEach(deviceids, (deviceid, callback) => {
      let err = deleteDevice(req.user, req.params.deviceid)
      if (err) {
        for (let type in err) {
          req.flash(type, err[type])
        }
        return res.redirect('/')
      }
    }, err => {
      if (err) {
        req.flash('error', 'Looping error. Please try again and report this issue if you see it again.')
        return res.redirect('/')
      }
      redisClient.del([`devices:${req.user}`, `users:${req.user}`], (err, result) => {
        if (err) {
          req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
          return res.redirect('/')
        }
        req.logout()
        req.flash('success', 'Your account has been deleted.')
        res.redirect('/')
      })
    })
  })
})
//

app.get('/register', (req, res) => {
  res.render('register', {
    user: req.user
  })
})

app.post('/register', (req, res) => {
  if (!req.body.username) {
    req.flash('error', 'You must specify a username.')
    return res.redirect('/register')
  }
  if (!usernameRegex.test(req.body.username)) {
    req.flash('error', 'Your username must only contain letters, numbers, hypen and underscore.')
    return res.redirect('/register')
  }
  if (!req.body.password) {
    req.flash('error', 'You must specify a password.')
    return res.redirect('/register')
  }
  if (!req.body.friendCode) {
    req.flash('error', 'You must specify a friend code.')
    return res.redirect('/register')
  }
  if (!fcRe.test(req.body.friendCode) || !verifyFc(req.body.friendCode)) {
    req.flash('error', 'You must specify a valid friend code.')
    return res.redirect('/register')
  }
  if (!req.body.agree) {
    req.flash('error', 'You must agree to the terms of service and privacy policy.')
    return res.redirect('/register')
  }
  redisClient.exists(`users:${req.body.username}`, (err, result) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect('/register')
    }
    if (result) {
      req.flash('error', 'That username is taken.')
      return res.redirect('/register')
    } else {
      bcrypt.hash(req.body.password, 10, (err, hash) => {
        if (err) {
          req.flash('Bcrypt error. Please try again and report this issue if you see it again.')
          return res.redirect('/register')
        }
        redisClient.hmset(`users:${req.body.username}`, {
          password: hash,
          friendCode: req.body.friendCode
        }, (err, result) => {
          if (err) {
            req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
            return res.redirect('/register')
          }
          req.login(req.body.username, (err) => {
            if (err) {
              req.flash('error', 'Login error. Please try again and report this issue if you see it again.')
              return res.redirect('/login')
            }
            req.flash('success', 'Account created successfully.')
            return res.redirect('/home')
          })
        })
      })
    }
  })
})

app.get('/login', (req, res) => {
  if (req.user) {
    res.redirect('/home') // already logged in
  } else {
    res.render('login')
  }
})

app.post('/login', passport.authenticate('local', {
  successRedirect: '/home',
  failureRedirect: '/login',
  failureFlash: true,
  successFlash: 'Login successful.'
}))

app.get('/logout', (req, res) => {
  req.logout()
  req.flash('success', 'You have been logged out.')
  res.redirect('/')
})

// work

app.get('/work', enforceLogin, (req, res) => {
  let array = []
  redisClient.smembers(`workingDevices:${req.user}`, (err, deviceids) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect('/')
    }
    async.forEach(deviceids, (deviceid, callback) => {
      redisClient.hgetall(`device:${deviceid}`, (err, device) => {
        if (err) {
          req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
          return res.redirect('/')
        }
        if (device) {
          device.id = deviceid
          array.push(device)
        } else {
          redisClient.srem(`workingDevices:${req.user}`, deviceid, (err, result) => {
            if (err) {
              req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
              return res.redirect('/')
            }
          })
        }
        callback()
      })
    }, err => {
      if (err) {
        req.flash('error', 'Looping error. Please try again and report this issue if you see it again.')
        return res.redirect('/')
      }
      redisClient.hget(`users:${req.user}`, 'workPoints', (err, workPoints) => {
        if (err) {
          req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
          return res.redirect('/')
        }
        res.render('work', {
          devices: array,
          user: req.user,
          workPoints: workPoints
        })
      })
    })
  })
})

app.get('/work/part1s', enforceLogin, (req, res) => {
  redisClient.spop('p1NeededDevices', (err, deviceid) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect('/work')
    }
    if (deviceid == null) {
      req.flash('error', 'No devices are avaliable at this time.')
      return res.redirect('/work')
    }
    redisClient.hget(`users:${req.user}`, 'friendCode', (err, friendCode) => {
      if (err) {
        req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
        return res.redirect('/work')
      }
      redisClient.hmset(`device:${deviceid}`, {
        workStartTime: Date.now(),
        worker: req.user,
        workerFriendCode: friendCode
      }, (err, result) => {
        if (err) {
          req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
          return res.redirect('/work')
        }
        redisClient.sadd('workingDevices', deviceid, (err, result) => {
          if (err) {
            req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
            return res.redirect('/work')
          }
          redisClient.sadd(`workingDevices:${req.user}`, deviceid, (err, result) => {
            if (err) {
              req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
              return res.redirect('/work')
            }
            res.redirect(`/work/part1/${deviceid}`)
          })
        })
      })
    })
  })
})

app.get('/work/part1/:deviceid', enforceLogin, (req, res) => {
  redisClient.hgetall(`device:${req.params.deviceid}`, (err, device) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect('/work')
    }
    if (!device) {
      req.flash('error', "This device doesn't exist.")
      return res.redirect('/work')
    }
    if (device.worker !== req.user) {
      req.flash('error', "You haven't been assigned to work on this device.")
      return res.redirect('/work')
    }
    device.id = req.params.deviceid
    res.render('part1', {
      device: device,
      user: req.user
    })
  })
})

app.post('/work/part1/:deviceid', enforceLogin, upload.fields([{
  name: 'p1',
  maxCount: 1
}]), (req, res) => {
  if (!Object.keys(req.files).length) {
    req.flash('error', 'You must upload a file.')
    return res.redirect(`/work/part1/${req.params.deviceid}`)
  } else {
    if (req.files.p1[0].size !== 4096) {
      req.flash('error', 'File is not a valid movable_part1.')
      return res.redirect(`/work/part1/${req.params.deviceid}`)
    }
    redisClient.hgetall(`device:${req.params.deviceid}`, (err, device) => {
      if (err) {
        req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
        return res.redirect(`/work/part1/${req.params.deviceid}`)
      }
      if (!device) {
        req.flash('error', "This device doesn't exist.")
        return res.redirect('/work')
      }
      if (device.worker !== req.user) {
        req.flash('error', "You haven't been assigned to work on this device.")
        return res.redirect('/work')
      }
      req.files.p1[0].buffer.write(device.id0.toLowerCase(), 0x10, 0x40)
      if (req.files.p1[0].buffer.readUIntBE(0, 4) === 0) {
        req.flash('error', 'Your movable_part1 appears to be blank. Did you wait for the user to add you back? Please try again.')
        return res.redirect(`/work/part1/${req.params.deviceid}`)
      }
      fs.writeFile(`static/ugc/part1/${req.params.deviceid}_part1.sed`, req.files.p1[0].buffer, (err) => {
        if (err) {
          req.flash('error', 'File upload error. Please try again and report this issue if you see it again.')
          return res.redirect(`/device/${req.params.deviceid}/edit`)
        }
        redisClient.srem('workingDevices', req.params.deviceid, (err, result) => {
          if (err) {
            req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
            return res.redirect(`/work/part1/${req.params.deviceid}`)
          }
          redisClient.srem(`workingDevices:${req.user}`, req.params.deviceid, (err, result) => {
            if (err) {
              req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
              return res.redirect(`/work/part1/${req.params.deviceid}`)
            }
            redisClient.hset(`device:${req.params.deviceid}`, 'p1', true, (err, result) => {
              if (err) {
                req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
                return res.redirect(`/work/part1/${req.params.deviceid}`)
              }
              if (device.autoMovable === 'on') {
                redisClient.sadd('movableNeededDevices', req.params.deviceid, (err, result) => {
                  if (err) {
                    req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
                    return res.redirect(`/work/part1/${req.params.deviceid}`)
                  }
                  redisClient.hincrby(`users:${req.user}`, 'workPoints', 2, (err, result) => {
                    if (err) {
                      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
                      return res.redirect(`/work/part1/${req.params.deviceid}`)
                    }
                    req.flash('success', 'Movable_part1 uploaded successfully! Thanks for supporting seedhelper.')
                    res.redirect('/work')
                  })
                })
              } else {
                redisClient.hincrby(`users:${req.user}`, 'workPoints', 2, (err, result) => {
                  if (err) {
                    req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
                    return res.redirect(`/work/part1/${req.params.deviceid}`)
                  }
                  req.flash('success', 'Movable_part1 uploaded successfully! Thanks for supporting seedhelper.')
                  res.redirect('/work')
                })
              }
            })
          })
        })
      })
    })
  }
})

app.get('/work/part1/:deviceid/fcinvalid', enforceLogin, (req, res) => {
  redisClient.hgetall(`device:${req.params.deviceid}`, (err, device) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect(`/work/part1/${req.params.deviceid}`)
    }
    if (!device) {
      req.flash('error', "This device doesn't exist.")
      return res.redirect('/work')
    }
    if (device.worker !== req.user) {
      req.flash('error', "You haven't been assigned to work on this device.")
      return res.redirect('/work')
    }
    redisClient.srem('workingDevices', req.params.deviceid, (err, result) => {
      if (err) {
        req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
        return res.redirect(`/work/part1/${req.params.deviceid}`)
      }
      redisClient.srem(`workingDevices:${req.user}`, req.params.deviceid, (err, result) => {
        if (err) {
          req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
          return res.redirect(`/work/part1/${req.params.deviceid}`)
        }
        redisClient.hset(`device:${req.params.deviceid}`, 'error', 'FC Invalid!', (err, result) => {
          if (err) {
            req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
            return res.redirect(`/work/part1/${req.params.deviceid}`)
          }
          req.flash('success', 'The user has been notified! Thanks for supporting seedhelper.')
          res.redirect('/work')
        })
      })
    })
  })
})

app.get('/work/part1/:deviceid/cancel', enforceLogin, (req, res) => {
  redisClient.hgetall(`device:${req.params.deviceid}`, (err, device) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect(`/work/part1/${req.params.deviceid}`)
    }
    if (!device) {
      req.flash('error', "This device doesn't exist.")
      return res.redirect('/work')
    }
    if (device.worker !== req.user) {
      req.flash('error', "You haven't been assigned to work on this device.")
      return res.redirect('/work')
    }
    redisClient.srem('workingDevices', req.params.deviceid, (err, result) => {
      if (err) {
        req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
        return res.redirect(`/work/part1/${req.params.deviceid}`)
      }
      redisClient.srem(`workingDevices:${req.user}`, req.params.deviceid, (err, result) => {
        if (err) {
          req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
          return res.redirect(`/work/part1/${req.params.deviceid}`)
        }
        redisClient.hdel(`device:${req.params.deviceid}`, 'worker', 'workStartTime', 'workerFriendCode', (err, result) => {
          if (err) {
            req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
            return res.redirect(`/work/part1/${req.params.deviceid}`)
          }
          redisClient.sadd('p1NeededDevices', req.params.deviceid, (err, result) => {
            if (err) {
              req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
              return res.redirect(`/work/part1/${req.params.deviceid}`)
            }
            req.flash('success', 'The work has been canceled! No need to feel bad, at least you didn\'t keep it running.')
            res.redirect('/work')
          })
        })
      })
    })
  })
})

app.get('/work/movables', enforceLogin, (req, res) => {
  redisClient.spop('movableNeededDevices', (err, deviceid) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect('/work')
    }
    if (deviceid == null) {
      req.flash('error', 'No devices are avaliable at this time.')
      return res.redirect('/work')
    }
    redisClient.hmset(`device:${deviceid}`, {
      'workStartTime': Date.now(),
      'worker': req.user
    }, (err, result) => {
      if (err) {
        req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
        return res.redirect('/work')
      }
      redisClient.sadd('workingDevices', deviceid, (err, result) => {
        if (err) {
          req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
          return res.redirect('/work')
        }
        redisClient.sadd(`workingDevices:${req.user}`, deviceid, (err, result) => {
          if (err) {
            req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
            return res.redirect('/work')
          }
          res.redirect(`/work/movable/${deviceid}`)
        })
      })
    })
  })
})

app.get('/work/movable/:deviceid', enforceLogin, (req, res) => {
  redisClient.hgetall(`device:${req.params.deviceid}`, (err, device) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect('/work')
    }
    if (!device) {
      req.flash('error', "This device doesn't exist.")
      return res.redirect('/work')
    }
    if (device.worker !== req.user) {
      req.flash('error', "You haven't been assigned to work on this device.")
      return res.redirect('/work')
    }
    device.id = req.params.deviceid
    res.render('movable', {
      device: device,
      user: req.user
    })
  })
})

app.post('/work/movable/:deviceid', enforceLogin, upload.fields([
  {
    name: 'movable',
    maxCount: 1
  },
  {
    name: 'msed',
    maxCount: 1
  }
]), (req, res) => {
  if (!Object.keys(req.files).length) {
    req.flash('error', 'You must upload a file.')
    return res.redirect(`/work/movable/${req.params.deviceid}`)
  } else {
    if (req.files.movable[0].size !== 320) {
      req.flash('error', 'File is not a valid movable.')
      return res.redirect(`/work/movable/${req.params.deviceid}`)
    }
    let toShaBuf = req.files.movable[0].buffer.slice(0x110, 0x120)
    // toShaBuf.swap16()
    let hash = crypto.createHash('sha256')
    hash.end(toShaBuf)
    let hashBuf = hash.read(16)
    let part1 = hashBuf.slice(0, 4).swap32()
    let part2 = hashBuf.slice(4, 8).swap32()
    let part3 = hashBuf.slice(8, 12).swap32()
    let part4 = hashBuf.slice(12, 16).swap32()
    let id0 = part1.toString('hex') + part2.toString('hex') + part3.toString('hex') + part4.toString('hex')
    redisClient.hgetall(`device:${req.params.deviceid}`, (err, device) => {
      if (err) {
        req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
        return res.redirect(`/work/movable/${req.params.deviceid}`)
      }
      if (device.worker !== req.user) {
        req.flash('error', "You haven't been assigned to work on this device.")
        return res.redirect('/work')
      }
      if (device.id0 !== id0) {
        req.flash('error', 'Movable.sed is invalid for this device.')
        return res.redirect(`/work/movable/${req.params.deviceid}`)
      }
      fs.writeFile(`static/ugc/movable/${req.params.deviceid}_movable.sed`, req.files.movable[0].buffer, (err) => {
        if (err) {
          req.flash('error', 'File upload error. Please try again and report this issue if you see it again.')
          return res.redirect(`/work/movable/${req.params.deviceid}`)
        }
        redisClient.srem('workingDevices', req.params.deviceid, (err, result) => {
          if (err) {
            req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
            return res.redirect(`/work/movable/${req.params.deviceid}`)
          }
          redisClient.srem(`workingDevices:${req.user}`, req.params.deviceid, (err, result) => {
            if (err) {
              req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
              return res.redirect(`/work/movable/${req.params.deviceid}`)
            }
            redisClient.hset(`device:${req.params.deviceid}`, 'movable', true, (err, result) => {
              if (err) {
                req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
                return res.redirect(`/work/movable/${req.params.deviceid}`)
              }
              redisClient.hincrby(`users:${req.user}`, 'workPoints', 5, (err, result) => {
                if (err) {
                  req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
                  return res.redirect(`/work/movable/${req.params.deviceid}`)
                }
                if (req.files.msed) {
                  if (req.files.msed[0].size !== 12) {
                    req.flash('error', 'File is not a valid msed_data.')
                    return res.redirect(`/work/movable/${req.params.deviceid}`)
                  }
                  let isNew = req.files.msed[0].buffer.readUInt32BE(8)
                  let data = req.files.msed[0].buffer.slice(0, 8)
                  let filename = 'static/ugc/data/lfcs.dat'
                  if (isNew) filename = 'static/ugc/data/lfcs_new.dat'
                  fs.appendFile(filename, data, err => {
                    if (err) {
                      req.flash('error', 'File upload error. Please try again and report this issue if you see it again.')
                      return res.redirect(`/work/movable/${req.params.deviceid}`)
                    }
                    redisClient.hincrby(`users:${req.user}`, 'workPoints', 3, (err, result) => {
                      if (err) {
                        req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
                        return res.redirect(`/work/movable/${req.params.deviceid}`)
                      }
                      req.flash('success', 'Movable and msed_data uploaded successfully! Thanks for supporting seedhelper.')
                      res.redirect('/work')
                    })
                  })
                } else {
                  req.flash('success', 'Movable uploaded successfully! Thanks for supporting seedhelper.')
                  res.redirect('/work')
                }
              })
            })
          })
        })
      })
    })
  }
})

app.get('/work/movable/:deviceid/cancel', enforceLogin, (req, res) => {
  redisClient.hgetall(`device:${req.params.deviceid}`, (err, device) => {
    if (err) {
      req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
      return res.redirect(`/work/movable/${req.params.deviceid}`)
    }
    if (!device) {
      req.flash('error', "This device doesn't exist.")
      return res.redirect('/work')
    }
    if (device.worker !== req.user) {
      req.flash('error', "You haven't been assigned to work on this device.")
      return res.redirect('/work')
    }
    redisClient.srem('workingDevices', req.params.deviceid, (err, result) => {
      if (err) {
        req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
        return res.redirect(`/work/movable/${req.params.deviceid}`)
      }
      redisClient.srem(`workingDevices:${req.user}`, req.params.deviceid, (err, result) => {
        if (err) {
          req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
          return res.redirect(`/work/movable/${req.params.deviceid}`)
        }
        redisClient.hdel(`device:${req.params.deviceid}`, 'worker', 'workStartTime', (err, result) => {
          if (err) {
            req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
            return res.redirect(`/work/movable/${req.params.deviceid}`)
          }
          redisClient.sadd('movableNeededDevices', req.params.deviceid, (err, result) => {
            if (err) {
              req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
              return res.redirect(`/work/movable/${req.params.deviceid}`)
            }
            req.flash('success', 'The work has been canceled! No need to feel bad, at least you didn\'t keep it running.')
            res.redirect('/work')
          })
        })
      })
    })
  })
})

app.get('/work/msed',  (req, res) => {
  res.render('msed', {
    user: req.user
  })
})

app.post('/work/msed', upload.fields([
  {
    name: 'msed'
  }
]), (req, res) => {
  if (req.files.msed) {
    async.forEach(req.files.msed, (file, callback) => {
      if (file.size !== 12) {
        req.flash('error', 'File is not a valid msed_data.')
        return res.redirect(`/work/msed`)
      }
      let isNew = file.buffer.readUInt32BE(8)
      let data = file.buffer.slice(0, 8)
      let filename = 'static/ugc/data/lfcs.dat'
      if (isNew) filename = 'static/ugc/data/lfcs_new.dat'
      fs.appendFile(filename, data, err => {
        if (err) {
          req.flash('error', 'File upload error. Please try again and report this issue if you see it again.')
          return res.redirect(`/work/msed`)
        }
        redisClient.hincrby(`users:${req.user || 'nologin'}`, 'workPoints', 3, (err, result) => {
          if (err) {
            req.flash('error', 'Redis error. Please try again and report this issue if you see it again.')
            return res.redirect(`/work/msed`)
          }
          callback()
        })
      })
    }, err => {
      if (err) {
        req.flash('error', 'Looping error. Please report this.')
        res.redirect('/work')
      }
      req.flash('success', 'Msed_data uploaded successfully! Thanks for supporting seedhelper.')
      res.redirect('/work')
    })
  } else {
    req.flash('error', 'No msed_data files were found.')
    res.redirect('/work/msed')
  }
})

// automatically repool dead tasks
setInterval(() => {
  redisClient.smembers('workingDevices', (err, deviceids) => {
    if (err) {
      console.log('Redis error in timer task')
    }
    async.forEach(deviceids, (deviceid, callback) => {
      redisClient.hgetall(`device:${deviceid}`, (err, device) => {
        if (err) {
          console.log('Redis error in timer task')
        }
        if (device.workStartTime + 7200000 < Date.now()) { // 2 hours
          console.log(`Worker ${device.worker} is taking too long, repooling...`)
        }
        redisClient.srem('workingDevices', deviceid, (err, result) => {
          if (err) {
            console.log('Redis error in timer task')
          }
          redisClient.srem(`workingDevices:${device.worker}`, deviceid, (err, result) => {
            if (err) {
              console.log('Redis error in timer task')
            }
            if (!device.p1) {
              redisClient.sadd('p1NeededDevices', deviceid, (err, result) => {
                if (err) {
                  console.log('Redis error in timer task')
                }
              })
            } else if (!device.movable) {
              redisClient.sadd('movableNeededDevices', deviceid, (err, result) => {
                if (err) {
                  console.log('Redis error in timer task')
                }
              })
            } else {
              console.log(`Actually ${device.worker} just got assigned a finished device.`)
            }
          })

        })
      })
    }, err => {
      if (err) {
        console.log('Looping error in timer task')
      }
    })
  })
}, 1200000) // 20 mins

// error handler
// 404
app.use((req, res, next) => {
  res.status(404).render('error', {error: 'That page does not exist.'})
})
// everything else
app.use((err, req, res, next) => {
  res.status(500).render('error', { error: err })
})

app.listen(process.env.PORT | 3000, () => console.log('App is listening'))
