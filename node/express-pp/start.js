// From https://github.com/GoogleContainerTools/distroless/tree/main/examples/nodejs/node-express
const express = require('express')
const { fork } = require('child_process');

const app = express()
const port = 3000


// PP vulnerable code
function isObject(obj) {
  console.log(typeof obj);
  return typeof obj === 'function' || typeof obj === 'object';
}

// Function vulnerable to prototype pollution
function merge(target, source) {
  for (let key in source) {
      if (isObject(target[key]) && isObject(source[key])) {
          merge(target[key], source[key]);
      } else {
          target[key] = source[key];
      }
  }
  return target;
}

function clone(target) {
  return merge({}, target);
}


// Treate incoming request
app.get('/', function(req, res){
  if (req.query.data){
    clone(JSON.parse((req.query.data))); //Call PP
    if (req.query.exec){
      fork('./something.js'); //Trigger execution
      res.send('Executed!');
    }
    else{
      res.send('Almost there!');
    }
  }
  else{
    res.send('Come back with some "data".');
  }
});

app.listen(port, () => console.log(`App listening on port ${port}!`))