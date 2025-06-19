package org.prebid.mobile.rendering.sdk;

import android.os.AsyncTask;
import androidx.compose.ui.node.B;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.SortedSet;
import java.util.TreeSet;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.loading.FileDownloadTask;
import org.prebid.mobile.rendering.networking.BaseNetworkTask;
import org.prebid.mobile.rendering.networking.BaseResponseHandler;
import org.prebid.mobile.rendering.sdk.scripts.JsScriptData;
import org.prebid.mobile.rendering.sdk.scripts.JsScriptRequesterImpl;
import org.prebid.mobile.rendering.sdk.scripts.JsScriptStorageImpl;
import org.prebid.mobile.rendering.utils.helpers.AppInfoManager;

/* loaded from: classes3.dex */
public class JsScriptsDownloader {
    public static final SortedSet b = Collections.synchronizedSortedSet(new TreeSet());
    public final JsScriptStorageImpl a;

    public static class ScriptDownloadListener implements BaseResponseHandler {
        public String a;
        public JsScriptStorageImpl b;

        public final void d(String str) {
            StringBuilder sb = new StringBuilder("Can't download script ");
            String str2 = this.a;
            LogUtil.b("JsScriptsDownloader", B.j(sb, str2, "(", str, ")"));
            JsScriptStorageImpl jsScriptStorageImpl = this.b;
            jsScriptStorageImpl.a.edit().remove(str2).apply();
            try {
                if (new File(jsScriptStorageImpl.b, str2).delete()) {
                    LogUtil.e(4, "JsScriptsStorage", "Not fully downloaded file removed.");
                }
            } catch (Throwable unused) {
            }
            JsScriptsDownloader.b.remove(str2);
        }
    }

    public JsScriptsDownloader(JsScriptStorageImpl jsScriptStorageImpl, JsScriptRequesterImpl jsScriptRequesterImpl) {
        this.a = jsScriptStorageImpl;
    }

    public final void a(JsScriptData jsScriptData, c cVar) throws IOException {
        String str = jsScriptData.a;
        SortedSet sortedSet = b;
        if (sortedSet.add(str)) {
            boolean zB = b(jsScriptData);
            String str2 = jsScriptData.a;
            if (zB) {
                sortedSet.remove(str2);
                return;
            }
            File file = new File(this.a.b, str2);
            File parentFile = file.getParentFile();
            if (parentFile != null && !parentFile.exists() && parentFile.mkdirs()) {
                LogUtil.e(4, "JsScriptsStorage", "Subfolders created");
            }
            BaseNetworkTask.GetUrlParams getUrlParams = new BaseNetworkTask.GetUrlParams();
            getUrlParams.a = jsScriptData.b;
            getUrlParams.d = AppInfoManager.a;
            getUrlParams.e = "GET";
            getUrlParams.c = "DownloadTask";
            JsScriptStorageImpl jsScriptStorageImpl = ((JSLibraryManager) cVar.a).c.a;
            ScriptDownloadListener scriptDownloadListener = new ScriptDownloadListener();
            scriptDownloadListener.a = str2;
            scriptDownloadListener.b = jsScriptStorageImpl;
            FileDownloadTask fileDownloadTask = new FileDownloadTask(scriptDownloadListener);
            fileDownloadTask.g = false;
            fileDownloadTask.f = file;
            if (!file.exists()) {
                try {
                    file.createNewFile();
                } catch (IOException unused) {
                    scriptDownloadListener.d("Error creating file");
                    throw new IllegalStateException("Error creating file");
                }
            }
            fileDownloadTask.e = scriptDownloadListener;
            fileDownloadTask.g = true;
            fileDownloadTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, getUrlParams);
        }
    }

    public final boolean b(JsScriptData jsScriptData) {
        String str = jsScriptData.a;
        JsScriptStorageImpl jsScriptStorageImpl = this.a;
        if (new File(jsScriptStorageImpl.b, str).exists()) {
            return jsScriptStorageImpl.a.contains(jsScriptData.a);
        }
        return false;
    }

    public final String c(JsScriptData jsScriptData) {
        try {
            JsScriptStorageImpl jsScriptStorageImpl = this.a;
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(new File(jsScriptStorageImpl.b, jsScriptData.a))));
            StringBuilder sb = new StringBuilder();
            while (true) {
                String line = bufferedReader.readLine();
                if (line == null) {
                    bufferedReader.close();
                    return sb.toString();
                }
                sb.append(line);
                sb.append("\n");
            }
        } catch (Throwable unused) {
            LogUtil.b("JsScriptsDownloader", "Can't read file: ".concat(jsScriptData.a));
            return null;
        }
    }
}
