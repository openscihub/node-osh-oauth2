var importFiles = require('./import');
var fs = require('fs');

var input = __dirname + '/../README.template.md';
var output = __dirname + '/../README.md';

var src = fs.readFileSync(input, {encoding: 'utf8'});

src = importFiles(src);

fs.writeFileSync(output, src);
