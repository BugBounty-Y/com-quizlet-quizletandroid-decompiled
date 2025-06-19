package org.prebid.mobile.rendering.sdk.scripts;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import java.io.File;

/* loaded from: classes3.dex */
public class JsScriptStorageImpl {
    public final SharedPreferences a;
    public final File b;

    public JsScriptStorageImpl(Context context) {
        this.a = PreferenceManager.getDefaultSharedPreferences(context);
        this.b = context.getFilesDir();
    }
}
