package com.pubmatic.sdk.common.log;

import android.util.Log;
import androidx.annotation.Keep;
import com.pubmatic.sdk.common.a;
import com.pubmatic.sdk.common.log.POBLog;

@Keep
/* loaded from: classes2.dex */
class POBDefaultLogger implements POBLog.POBLogging {
    @Override // com.pubmatic.sdk.common.log.POBLog.POBLogging
    public void log(POBLog.POBLogMessage pOBLogMessage) {
        int i = a.a[pOBLogMessage.mLogLevel.ordinal()];
        if (i == 1) {
            Log.i(pOBLogMessage.mTAG, pOBLogMessage.mMsg);
        } else if (i == 2) {
            Log.w(pOBLogMessage.mTAG, pOBLogMessage.mMsg);
        }
        if (pOBLogMessage.mLogLevel == a.EnumC0007a.Error) {
            Log.e(pOBLogMessage.mTAG, pOBLogMessage.mMsg);
        }
    }
}
