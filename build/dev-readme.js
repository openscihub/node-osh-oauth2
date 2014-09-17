var fs = require('fs');
var OAuth2 = require('..');


function error(msg) {
  console.log(msg);
  //process.exit();
}

var readme = fs.readFileSync(
  __dirname + '/../README.template.md',
  {encoding: 'utf8'}
);

// Find short RFC standard links.
readme = readme.replace(
  /oauth2#([.0-9]+)/g,
  'http://tools.ietf.org/html/rfc6749#section-$1'
);

// 

var flowNames = {
  AUTH: 'Authorization flows',
  TOKEN: 'Token flows',
  PASSWORD_TOKEN: 'Password token flow',
  CLIENT_TOKEN: 'Client token flow',
  CODE_TOKEN: 'Code token flow',
  IMPLICIT: 'Implicit authorization',
  CODE_AUTH: 'Code authorization',
  DECISION: 'Decision flow',
  SCOPE: 'Resource flow'
};
var flowId;
var fns = {};
var fn;
var next;
var prev;
var nav;
var index;
var larr = '&#8592;';
var rarr = '&#8594;';
var flowName;
var last;
var fnName;
var re;

// Replace flow headings with nice names and insert flow outlines
// where requested in template.

for (flowId in OAuth2.FLOWS) {
  flowName = flowNames[flowId];

  // Heading regexp
  re = new RegExp('^(#+\\s+)FLOWS\.' + flowId, 'gm');
  if (!re.test(readme)) {
    error('Document FLOWS.' + flowId + ' ya big jerk!');
  }
  re.lastIndex = 0;

  // Replace heading.
  readme = readme.replace(
    re,
    function(match, heading) {
      return heading + flowName;
    }
  );

  // Insert list of flow middleware (linked)
  readme = readme.replace(
    new RegExp('\\{FLOWS\.' + flowId + '\\}', 'g'),
    OAuth2.FLOWS[flowId].map(function(fnName) {
      return '- [' + fnName + '](#' + fnName.toLowerCase() + ')';
    }).join('\n')
  );

  // Replace FLOWS.<ID> with link to heading
  readme = readme.replace(
    new RegExp('FLOWS\.' + flowId, 'g'),
    function() {
      return (
        '[' + flowName + '](#' +
        flowName.toLowerCase().replace(/ /g, '-') +
        ')'
      );
    }
  );
}

//  Gather all expected middleware and the flows in which they appear.
//  {
//    validateAuthRequest: {
//      AUTH: 1 // index in flow
//    }
//  }
//
for (flowId in OAuth2.FLOWS) {
  //console.log(flowId);
  OAuth2.FLOWS[flowId].forEach(function(fnName, index) {
    fn = fns[fnName] || {};
    fn[flowId] = index;
    fns[fnName] = fn;
  });
}

//console.log(JSON.stringify(fns, null, 2));

// Add flow navigation to each middleware description.
for (fnName in fns) {
  fn = fns[fnName];
  nav = '\n';
  for (flowId in fn) {
    index = fn[flowId];
    flowName = flowNames[flowId];
    flowLink = flowName.toLowerCase().replace(/ /g, '-');
    prev = OAuth2.FLOWS[flowId][index - 1];
    next = OAuth2.FLOWS[flowId][index + 1];
    nav += (
      '\n- ' +
      (prev ? ('[' + larr + '](#' + prev.toLowerCase() + ') ') : '') +
      '[' + flowName + '](#' + flowLink + ') ' +
      (next ? ('[' + rarr + '](#' + next.toLowerCase() + ')') : '')
    );
  }
  re = new RegExp('^(#+\\s+)' + fnName, 'gm');
  if (!re.test(readme)) {
    error('Document ' + fnName + ' ya big jerk!');
  }
  re.lastIndex = 0;

  readme = readme.replace(
    re,
    function(match, heading) {
      return match + nav;
    }
  );
}


fs.writeFileSync(__dirname + '/../README.md', readme);
