function jxbootstrap(basepath,script) {
  var JX_NUM_INCLUDES = 6;
  var JX_NUM_INCLUDED = 0;
  function jxScriptLoaded() { 
    if (++JX_NUM_INCLUDED == JX_NUM_INCLUDES) {
      if (script) $.getScript(script);
    }

  }

  $.getScript(basepath+'/json2.js', jxScriptLoaded);
  $.getScript(basepath+'/strophejs/src/b64.js', jxScriptLoaded);
  $.getScript(basepath+'/strophejs/src/md5.js', jxScriptLoaded);
  $.getScript(basepath+'/strophejs/src/sha1.js', jxScriptLoaded);
  $.getScript(basepath+'/strophejs/src/strophe.js', jxScriptLoaded);
  $.getScript(basepath+'/junction.js', jxScriptLoaded);

}