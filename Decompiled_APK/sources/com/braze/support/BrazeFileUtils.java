package com.braze.support;

import android.content.res.AssetManager;
import android.net.TrafficStats;
import android.net.Uri;
import com.braze.AbstractC1484j;
import com.braze.Braze;
import com.braze.P;
import com.braze.storage.D;
import com.braze.storage.F;
import com.braze.support.BrazeLogger;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.B;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.StringsKt;

@Metadata
/* loaded from: classes.dex */
public abstract class BrazeFileUtils {
    private static final String TAG = BrazeLogger.INSTANCE.getBrazeLogTag("BrazeFileUtils");
    public static final List<String> REMOTE_SCHEMES = B.j("http", "https", "ftp", "ftps", "about", "javascript");

    public static final void deleteFileOrDirectory(File fileOrDirectory) {
        Intrinsics.checkNotNullParameter(fileOrDirectory, "fileOrDirectory");
        if (kotlin.io.k.e(fileOrDirectory)) {
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new o(fileOrDirectory, 0), 12, (Object) null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String deleteFileOrDirectory$lambda$0(File file) {
        return "Could not recursively delete " + file.getName();
    }

    public static final Pair<File, Map<String, String>> downloadFileToPath(String downloadDirectoryAbsolutePath, String remoteFileUrl, String outputFilename, String str) throws Exception {
        Intrinsics.checkNotNullParameter(downloadDirectoryAbsolutePath, "downloadDirectoryAbsolutePath");
        Intrinsics.checkNotNullParameter(remoteFileUrl, "remoteFileUrl");
        Intrinsics.checkNotNullParameter(outputFilename, "outputFilename");
        TrafficStats.setThreadStatsTag(1337);
        if (Braze.Companion.getOutboundNetworkRequestsOffline()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new D(remoteFileUrl, 18), 12, (Object) null);
            throw new Exception(AbstractC1484j.a("SDK is offline. File not downloaded for url: ", remoteFileUrl));
        }
        if (StringsKt.O(downloadDirectoryAbsolutePath)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new F(7), 12, (Object) null);
            throw new Exception("Download directory is blank. File not downloaded.");
        }
        if (StringsKt.O(remoteFileUrl)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new F(6), 12, (Object) null);
            throw new Exception("Zip file url is blank. File not downloaded.");
        }
        if (StringsKt.O(outputFilename)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new F(5), 12, (Object) null);
            throw new Exception("Output filename is blank. File not downloaded.");
        }
        try {
            try {
                new File(downloadDirectoryAbsolutePath).mkdirs();
                if (str != null && !StringsKt.O(str)) {
                    outputFilename = outputFilename.concat(str);
                }
                File file = new File(downloadDirectoryAbsolutePath, outputFilename);
                HttpURLConnection httpURLConnectionA = com.braze.communication.g.a.a(new URL(remoteFileUrl));
                int responseCode = httpURLConnectionA.getResponseCode();
                if (responseCode != 200) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new P(responseCode, remoteFileUrl), 14, (Object) null);
                    throw new Exception("HTTP response code was " + responseCode + ". File with url " + remoteFileUrl + " could not be downloaded.");
                }
                DataInputStream dataInputStream = new DataInputStream(httpURLConnectionA.getInputStream());
                try {
                    FileOutputStream fileOutputStream = new FileOutputStream(file);
                    try {
                        AbstractC3332e.b(dataInputStream, fileOutputStream);
                        fileOutputStream.close();
                        dataInputStream.close();
                        Map<String, List<String>> headerFields = httpURLConnectionA.getHeaderFields();
                        Intrinsics.checkNotNullExpressionValue(headerFields, "getHeaderFields(...)");
                        LinkedHashMap linkedHashMapA = l.a(headerFields);
                        httpURLConnectionA.disconnect();
                        return new Pair<>(file, linkedHashMapA);
                    } finally {
                    }
                } catch (Throwable th) {
                    try {
                        throw th;
                    } catch (Throwable th2) {
                        AbstractC3336f.c(dataInputStream, th);
                        throw th2;
                    }
                }
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new D(remoteFileUrl, 17), 8, (Object) null);
                throw new Exception("Exception during download of file from url : ".concat(remoteFileUrl));
            }
        } finally {
        }
    }

    public static /* synthetic */ Pair downloadFileToPath$default(String str, String str2, String str3, String str4, int i, Object obj) {
        if ((i & 8) != 0) {
            str4 = null;
        }
        return downloadFileToPath(str, str2, str3, str4);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String downloadFileToPath$lambda$11(String str) {
        return AbstractC1484j.a("Exception during download of file from url : ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String downloadFileToPath$lambda$4(String str) {
        return AbstractC1484j.a("SDK is offline. File not downloaded for url: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String downloadFileToPath$lambda$5() {
        return "Download directory null or blank. File not downloaded.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String downloadFileToPath$lambda$6() {
        return "Zip file url null or blank. File not downloaded.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String downloadFileToPath$lambda$7() {
        return "Output filename null or blank. File not downloaded.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String downloadFileToPath$lambda$8(int i, String str) {
        return "HTTP response code was " + i + ". File with url " + str + " could not be downloaded.";
    }

    public static final String getAssetFileStringContents(AssetManager assetManager, String assetPath) throws IOException {
        Intrinsics.checkNotNullParameter(assetManager, "<this>");
        Intrinsics.checkNotNullParameter(assetPath, "assetPath");
        InputStream inputStreamOpen = assetManager.open(assetPath);
        Intrinsics.checkNotNullExpressionValue(inputStreamOpen, "open(...)");
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStreamOpen, Charsets.UTF_8), 8192);
        try {
            String strB = AbstractC3340g.b(bufferedReader);
            bufferedReader.close();
            return strB;
        } finally {
        }
    }

    public static final boolean isLocalUri(Uri uri) {
        Intrinsics.checkNotNullParameter(uri, "<this>");
        String scheme = uri.getScheme();
        return scheme == null || StringsKt.O(scheme) || scheme.equals("file");
    }

    public static final boolean isRemoteUri(Uri uri) {
        Intrinsics.checkNotNullParameter(uri, "<this>");
        String scheme = uri.getScheme();
        if (scheme != null && !StringsKt.O(scheme)) {
            return REMOTE_SCHEMES.contains(scheme);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, TAG, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new F(4), 12, (Object) null);
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isRemoteUri$lambda$3() {
        return "Null or blank Uri scheme.";
    }
}
