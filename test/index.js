const listener = require('../index');
let path = new listener('c:\\drive');
path.onChange(function(file, data) {
  console.log(file + ' => ', data);
});
console.log('Listen changes');