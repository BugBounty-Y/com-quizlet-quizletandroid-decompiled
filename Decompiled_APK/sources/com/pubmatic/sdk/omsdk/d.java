package com.pubmatic.sdk.omsdk;

import android.webkit.URLUtil;
import androidx.annotation.NonNull;
import com.iab.omid.library.pubmatic.adsession.VerificationScriptResource;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.utility.o;
import com.pubmatic.sdk.common.viewability.j;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class d {
    public static final String TAG = "OMSDK";

    @NonNull
    public static List<VerificationScriptResource> getVerificationScriptResourceList(List<? extends j> list) {
        ArrayList arrayList = new ArrayList();
        if (list != null) {
            for (j jVar : list) {
                List<String> javaScriptResource = jVar.getJavaScriptResource();
                if (javaScriptResource != null) {
                    for (String str : javaScriptResource) {
                        if (URLUtil.isValidUrl(str)) {
                            try {
                                URL url = new URL(str);
                                arrayList.add((o.isNullOrEmpty(jVar.getVendorKey()) || o.isNullOrEmpty(jVar.getVerificationParameter())) ? VerificationScriptResource.createVerificationScriptResourceWithoutParameters(url) : VerificationScriptResource.createVerificationScriptResourceWithParameters(jVar.getVendorKey(), url, jVar.getVerificationParameter()));
                            } catch (Exception unused) {
                                POBLog.warn(TAG, "Unable to form verification script resource for resource url : %s", str);
                            }
                        }
                    }
                } else {
                    POBLog.debug(TAG, "Javascript resources are null", new Object[0]);
                }
            }
        }
        return arrayList;
    }
}
