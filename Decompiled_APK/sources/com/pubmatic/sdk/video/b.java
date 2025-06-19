package com.pubmatic.sdk.video;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.network.n;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public class b {

    @NonNull
    private final n a;

    public b(@NonNull n nVar) {
        this.a = nVar;
    }

    private boolean a(a aVar) {
        return (aVar == null || convertToPOBError(aVar) == null) ? false : true;
    }

    public static com.pubmatic.sdk.common.h convertToPOBError(@NonNull a aVar) {
        int errorCode = aVar.getErrorCode();
        if (errorCode != 200 && errorCode != 201 && errorCode != 405) {
            if (errorCode != 900) {
                switch (errorCode) {
                    case 100:
                    case 101:
                    case 102:
                        return new com.pubmatic.sdk.common.h(1007, aVar.getErrorMessage());
                    default:
                        switch (errorCode) {
                            case 300:
                                break;
                            case 301:
                            case 304:
                                return new com.pubmatic.sdk.common.h(1005, aVar.getErrorMessage());
                            default:
                                switch (errorCode) {
                                    case 400:
                                    case 403:
                                        break;
                                    case 401:
                                        break;
                                    case 402:
                                        return new com.pubmatic.sdk.common.h(1003, aVar.getErrorMessage());
                                    default:
                                        switch (errorCode) {
                                            case a.GENERAL_NONLINEAR_AD_ERROR /* 500 */:
                                            case 503:
                                                break;
                                            case 501:
                                            case 502:
                                                break;
                                            default:
                                                return null;
                                        }
                                }
                            case 302:
                            case 303:
                                return new com.pubmatic.sdk.common.h(1002, aVar.getErrorMessage());
                        }
                }
            }
            return new com.pubmatic.sdk.common.h(1006, aVar.getErrorMessage());
        }
        return new com.pubmatic.sdk.common.h(1009, aVar.getErrorMessage());
    }

    public void executeVastErrors(List<String> list, @NonNull a aVar) {
        executeVastErrorsWithMacros(list, null, aVar, null);
    }

    public void executeVastErrorsWithMacros(List<String> list, Map<Object, Object> map, @NonNull a aVar, Map<String, String> map2) {
        POBLog.debug("POBVastErrorHandler", "Vast error occurred: %s", aVar.toString());
        if (list == null || list.isEmpty()) {
            POBLog.warn("POBVastErrorHandler", "Tracker url list is empty for vast error: %d", new Object[0]);
            return;
        }
        if (!a(aVar)) {
            POBLog.warn("POBVastErrorHandler", "Skipped tracker execution for vast error: %d", Integer.valueOf(aVar.getErrorCode()));
            return;
        }
        if (map == null) {
            map = Collections.synchronizedMap(new HashMap(1));
        }
        map.put("[ERRORCODE]", "" + aVar.getErrorCode());
        this.a.handleTrackersForError(list, map, map2);
    }
}
