
// launcher.ts is the launcher for BDS
// These scripts are run before launching BDS
// So there are no 'server' variable yet
// launcher.ts will import ./index.ts after launching BDS.

import 'bdsx/checkcore';
import 'bdsx/checkmd5';
import { bedrockServer } from "bdsx/launcher";
import { remapAndPrintError } from "bdsx/source-map-support";
import colors = require('colors');

// prank
console.log(colors.rainbow('       ///////////////'));
console.log(colors.rainbow('       //// BDSX2 ////'));
console.log(colors.rainbow('       ///////////////'));

(async()=>{

    bedrockServer.close.on(()=>{
        console.log('[BDSX] bedrockServer is Closed');
        setTimeout(()=>{
            console.log('[BDSX] node.js is processing...');
        }, 3000).unref();
    });

    // launch BDS
    console.log('[BDSX] bedrockServer launching...');
    await bedrockServer.launch();

    /**
     * send stdin to bedrockServer.executeCommandOnConsole
     * without this, you need to control stdin manually
     */
    bedrockServer.DefaultStdInHandler.install();
    
    // run index
    require('./index');
})().catch(remapAndPrintError);
