package org.prebid.mobile.rendering.loading;

import android.content.Context;
import java.io.File;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.networking.BaseNetworkTask;
import org.prebid.mobile.rendering.sdk.JSLibraryManager;
import org.prebid.mobile.rendering.sdk.JsScriptsDownloader;
import org.prebid.mobile.rendering.sdk.PrebidContextHolder;

/* loaded from: classes3.dex */
public class FileDownloadTask extends BaseNetworkTask {
    public JsScriptsDownloader.ScriptDownloadListener e;
    public File f;
    public boolean g;

    /* JADX WARN: Code restructure failed: missing block: B:12:0x003c, code lost:
    
        if (r9 != false) goto L13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x003e, code lost:
    
        ((java.net.HttpURLConnection) r10).disconnect();
     */
    /* JADX WARN: Code restructure failed: missing block: B:14:0x0043, code lost:
    
        return r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x0064, code lost:
    
        if (r9 != false) goto L13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x006c, code lost:
    
        if (r9 != false) goto L13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00a4, code lost:
    
        return r3;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:30:0x009d -> B:37:0x00a4). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:31:0x009f -> B:37:0x00a4). Please report as a decompilation issue!!! */
    @Override // org.prebid.mobile.rendering.networking.BaseNetworkTask
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final org.prebid.mobile.rendering.networking.BaseNetworkTask.GetUrlResult a(int r9, java.net.URLConnection r10) {
        /*
            r8 = this;
            java.lang.String r0 = "download of media failed "
            java.lang.String r1 = "download of media failed: "
            java.lang.String r2 = "FileDownloader encountered file with "
            org.prebid.mobile.rendering.networking.BaseNetworkTask$GetUrlResult r3 = new org.prebid.mobile.rendering.networking.BaseNetworkTask$GetUrlResult
            r3.<init>()
            r4 = 200(0xc8, float:2.8E-43)
            if (r9 == r4) goto L21
            org.prebid.mobile.rendering.errors.ServerWrongStatusCode r10 = new org.prebid.mobile.rendering.errors.ServerWrongStatusCode
            java.lang.String r0 = "Server returned "
            java.lang.String r1 = " status code"
            java.lang.String r9 = androidx.camera.camera2.internal.AbstractC0147y.c(r9, r0, r1)
            java.lang.String r0 = "Server error"
            r10.<init>(r0, r9)
            r3.a = r10
            return r3
        L21:
            boolean r9 = r8.g     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            if (r9 != 0) goto L67
            int r9 = r10.getContentLength()     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            long r4 = (long) r9     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            r6 = 26214400(0x1900000, double:1.29516345E-316)
            int r4 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r4 <= 0) goto L48
            java.lang.Exception r9 = new java.lang.Exception     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            java.lang.String r2 = "FileDownloader encountered a file larger than SDK cap of 26214400"
            r9.<init>(r2)     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            r3.a = r9     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            boolean r9 = r10 instanceof java.net.HttpURLConnection
            if (r9 == 0) goto La4
        L3e:
            java.net.HttpURLConnection r10 = (java.net.HttpURLConnection) r10
            r10.disconnect()
            return r3
        L44:
            r9 = move-exception
            goto La5
        L46:
            r9 = move-exception
            goto L6f
        L48:
            if (r9 > 0) goto L67
            java.lang.Exception r4 = new java.lang.Exception     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            java.lang.StringBuilder r5 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            r5.<init>(r2)     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            r5.append(r9)     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            java.lang.String r9 = " content length"
            r5.append(r9)     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            java.lang.String r9 = r5.toString()     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            r4.<init>(r9)     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            r3.a = r4     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            boolean r9 = r10 instanceof java.net.HttpURLConnection
            if (r9 == 0) goto La4
            goto L3e
        L67:
            r8.f(r10)     // Catch: java.lang.Throwable -> L44 java.io.IOException -> L46
            boolean r9 = r10 instanceof java.net.HttpURLConnection
            if (r9 == 0) goto La4
            goto L3e
        L6f:
            java.lang.String r2 = "LibraryDownloadTask"
            java.lang.StringBuilder r4 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L44
            r4.<init>(r1)     // Catch: java.lang.Throwable -> L44
            java.lang.String r1 = android.util.Log.getStackTraceString(r9)     // Catch: java.lang.Throwable -> L44
            r4.append(r1)     // Catch: java.lang.Throwable -> L44
            java.lang.String r1 = r4.toString()     // Catch: java.lang.Throwable -> L44
            org.prebid.mobile.LogUtil.b(r2, r1)     // Catch: java.lang.Throwable -> L44
            java.lang.Exception r1 = new java.lang.Exception     // Catch: java.lang.Throwable -> L44
            java.lang.StringBuilder r2 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L44
            r2.<init>(r0)     // Catch: java.lang.Throwable -> L44
            java.lang.String r9 = r9.getMessage()     // Catch: java.lang.Throwable -> L44
            r2.append(r9)     // Catch: java.lang.Throwable -> L44
            java.lang.String r9 = r2.toString()     // Catch: java.lang.Throwable -> L44
            r1.<init>(r9)     // Catch: java.lang.Throwable -> L44
            r3.a = r1     // Catch: java.lang.Throwable -> L44
            boolean r9 = r10 instanceof java.net.HttpURLConnection
            if (r9 == 0) goto La4
            java.net.HttpURLConnection r10 = (java.net.HttpURLConnection) r10
            r10.disconnect()
        La4:
            return r3
        La5:
            boolean r0 = r10 instanceof java.net.HttpURLConnection
            if (r0 == 0) goto Lae
            java.net.HttpURLConnection r10 = (java.net.HttpURLConnection) r10
            r10.disconnect()
        Lae:
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: org.prebid.mobile.rendering.loading.FileDownloadTask.a(int, java.net.URLConnection):org.prebid.mobile.rendering.networking.BaseNetworkTask$GetUrlResult");
    }

    @Override // org.prebid.mobile.rendering.networking.BaseNetworkTask, android.os.AsyncTask
    /* renamed from: c, reason: merged with bridge method [inline-methods] */
    public final void onPostExecute(BaseNetworkTask.GetUrlResult getUrlResult) {
        Exception exc = getUrlResult.a;
        JsScriptsDownloader.ScriptDownloadListener scriptDownloadListener = this.e;
        if (exc != null) {
            LogUtil.e(3, "LibraryDownloadTask", "download of media failed" + getUrlResult.a);
            if (scriptDownloadListener != null) {
                scriptDownloadListener.d(getUrlResult.a.getMessage());
                return;
            }
            return;
        }
        if (scriptDownloadListener != null) {
            String path = this.f.getPath();
            int iLastIndexOf = path.lastIndexOf("/");
            if (iLastIndexOf != -1) {
                path.substring(iLastIndexOf);
            }
            StringBuilder sb = new StringBuilder("JS scripts saved: ");
            String str = scriptDownloadListener.a;
            sb.append(str);
            LogUtil.e(4, "JsScriptsDownloader", sb.toString());
            scriptDownloadListener.b.a.edit().putBoolean(str, true).apply();
            Context contextA = PrebidContextHolder.a();
            if (contextA != null) {
                JSLibraryManager.b(contextA).c();
            }
            JsScriptsDownloader.b.remove(str);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0036  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x003b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f(java.net.URLConnection r6) throws java.lang.Throwable {
        /*
            r5 = this;
            r0 = 0
            java.io.FileOutputStream r1 = new java.io.FileOutputStream     // Catch: java.lang.Throwable -> L2d java.io.IOException -> L30
            java.io.File r2 = r5.f     // Catch: java.lang.Throwable -> L2d java.io.IOException -> L30
            r1.<init>(r2)     // Catch: java.lang.Throwable -> L2d java.io.IOException -> L30
            java.io.InputStream r0 = r6.getInputStream()     // Catch: java.lang.Throwable -> L1c java.io.IOException -> L21
            r6 = 16384(0x4000, float:2.2959E-41)
            byte[] r6 = new byte[r6]     // Catch: java.lang.Throwable -> L1c java.io.IOException -> L21
        L10:
            int r2 = r0.read(r6)     // Catch: java.lang.Throwable -> L1c java.io.IOException -> L21
            r3 = -1
            if (r2 == r3) goto L26
            r3 = 0
            r1.write(r6, r3, r2)     // Catch: java.lang.Throwable -> L1c java.io.IOException -> L21
            goto L10
        L1c:
            r6 = move-exception
            r4 = r1
            r1 = r0
            r0 = r4
            goto L34
        L21:
            r6 = move-exception
            r4 = r1
            r1 = r0
            r0 = r4
            goto L32
        L26:
            r1.close()
            r0.close()
            return
        L2d:
            r6 = move-exception
            r1 = r0
            goto L34
        L30:
            r6 = move-exception
            r1 = r0
        L32:
            throw r6     // Catch: java.lang.Throwable -> L33
        L33:
            r6 = move-exception
        L34:
            if (r0 == 0) goto L39
            r0.close()
        L39:
            if (r1 == 0) goto L3e
            r1.close()
        L3e:
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: org.prebid.mobile.rendering.loading.FileDownloadTask.f(java.net.URLConnection):void");
    }
}
