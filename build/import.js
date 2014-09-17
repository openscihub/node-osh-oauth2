var path = require('path');
var fs = require('fs');

module.exports = function(src) {
  return src.replace(/IMPORT (\S+)/, function(match, filename) {
    return fs.readFileSync(
      path.resolve(__dirname, '..', filename),
      {encoding: 'utf8'}
    );
  });
};
