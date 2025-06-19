package org.prebid.mobile.rendering.sdk;

import android.content.Context;
import java.util.SortedSet;
import java.util.concurrent.atomic.AtomicBoolean;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.sdk.scripts.JsScriptData;
import org.prebid.mobile.rendering.sdk.scripts.JsScriptRequesterImpl;
import org.prebid.mobile.rendering.sdk.scripts.JsScriptStorageImpl;

/* loaded from: classes3.dex */
public class JSLibraryManager {
    public static JSLibraryManager d;
    public String a;
    public String b;
    public JsScriptsDownloader c;

    public static class BackgroundScriptReader implements Runnable {
        public static final AtomicBoolean c = new AtomicBoolean(false);
        public final JsScriptsDownloader a;
        public final JSLibraryManager b;

        public BackgroundScriptReader(JsScriptsDownloader jsScriptsDownloader, JSLibraryManager jSLibraryManager) {
            this.a = jsScriptsDownloader;
            this.b = jSLibraryManager;
        }

        @Override // java.lang.Runnable
        public final void run() {
            JsScriptData jsScriptData = JsScriptData.c;
            JsScriptsDownloader jsScriptsDownloader = this.a;
            String strC = jsScriptsDownloader.c(jsScriptData);
            String strC2 = jsScriptsDownloader.c(JsScriptData.d);
            JSLibraryManager jSLibraryManager = this.b;
            jSLibraryManager.b = strC;
            jSLibraryManager.a = strC2;
            c.set(false);
        }
    }

    public static JSLibraryManager b(Context context) {
        if (d == null) {
            synchronized (JSLibraryManager.class) {
                try {
                    if (d == null) {
                        JSLibraryManager jSLibraryManager = new JSLibraryManager();
                        jSLibraryManager.a = "";
                        jSLibraryManager.b = "";
                        SortedSet sortedSet = JsScriptsDownloader.b;
                        jSLibraryManager.c = new JsScriptsDownloader(new JsScriptStorageImpl(context), new JsScriptRequesterImpl());
                        d = jSLibraryManager;
                    }
                } finally {
                }
            }
        }
        return d;
    }

    public final void a() {
        JsScriptsDownloader jsScriptsDownloader = this.c;
        JsScriptData jsScriptData = JsScriptData.c;
        boolean zB = jsScriptsDownloader.b(jsScriptData);
        JsScriptData jsScriptData2 = JsScriptData.d;
        if (zB && jsScriptsDownloader.b(jsScriptData2)) {
            if (this.b.isEmpty() || this.a.isEmpty()) {
                c();
                return;
            }
            return;
        }
        c cVar = new c(this);
        try {
            jsScriptsDownloader.a(jsScriptData, cVar);
            jsScriptsDownloader.a(jsScriptData2, cVar);
        } catch (Throwable th) {
            LogUtil.c(th);
        }
    }

    public final void c() {
        JsScriptsDownloader jsScriptsDownloader = this.c;
        if (jsScriptsDownloader.b(JsScriptData.c) && jsScriptsDownloader.b(JsScriptData.d)) {
            if ((this.b.isEmpty() || this.a.isEmpty()) && BackgroundScriptReader.c.compareAndSet(false, true)) {
                new Thread(new BackgroundScriptReader(jsScriptsDownloader, this)).start();
            }
        }
    }
}
