package com.pubmatic.sdk.common.network;

import android.content.Context;
import androidx.annotation.NonNull;
import java.io.File;

/* loaded from: classes2.dex */
public class o {
    public static m newRequestQueue(@NonNull Context context, @NonNull com.android.volley.f fVar) {
        m mVar = new m(new com.android.volley.toolbox.d(new File(context.getCacheDir(), "pmvolley"), 0), fVar);
        mVar.start();
        return mVar;
    }
}
