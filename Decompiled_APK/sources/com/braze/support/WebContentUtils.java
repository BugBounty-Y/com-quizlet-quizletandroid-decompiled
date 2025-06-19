package com.braze.support;

import android.content.Context;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.navigation.compose.C1277j;
import com.braze.AbstractC1476b;
import com.braze.AbstractC1484j;
import com.braze.C1480f;
import com.braze.C1481g;
import com.braze.support.BrazeLogger;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlin.text.D;
import kotlin.text.StringsKt;
import kotlin.text.StringsKt__StringsKt;

@Metadata
/* loaded from: classes.dex */
public final class WebContentUtils {
    public static final WebContentUtils INSTANCE = new WebContentUtils();

    private WebContentUtils() {
    }

    public static final File getHtmlInAppMessageAssetCacheDirectory(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return new File(context.getCacheDir().getPath() + "/braze-html-inapp-messages");
    }

    public static final String getLocalHtmlUrlFromRemoteUrl(File localDirectory, String remoteZipUrl) {
        Intrinsics.checkNotNullParameter(localDirectory, "localDirectory");
        Intrinsics.checkNotNullParameter(remoteZipUrl, "remoteZipUrl");
        if (StringsKt.O(remoteZipUrl)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new v(11), 6, (Object) null);
            return null;
        }
        String absolutePath = localDirectory.getAbsolutePath();
        String strValueOf = String.valueOf(IntentUtils.getRequestCode());
        String str = absolutePath + '/' + strValueOf;
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        WebContentUtils webContentUtils = INSTANCE;
        BrazeLogger.brazelog$default(brazeLogger, (Object) webContentUtils, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1481g(25, remoteZipUrl, str), 7, (Object) null);
        try {
            File file = (File) BrazeFileUtils.downloadFileToPath(str, remoteZipUrl, strValueOf, ".zip").a;
            BrazeLogger.brazelog$default(brazeLogger, (Object) webContentUtils, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1481g(26, remoteZipUrl, str), 7, (Object) null);
            if (unpackZipIntoDirectory(str, file)) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) webContentUtils, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new w(str, 3), 7, (Object) null);
                return str;
            }
            BrazeLogger.brazelog$default(brazeLogger, (Object) webContentUtils, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new v(12), 6, (Object) null);
            BrazeFileUtils.deleteFileOrDirectory(new File(str));
            return null;
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new w(remoteZipUrl, 4), 4, (Object) null);
            BrazeFileUtils.deleteFileOrDirectory(new File(str));
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalHtmlUrlFromRemoteUrl$lambda$0() {
        return "Remote zip url is empty. No local URL will be created.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalHtmlUrlFromRemoteUrl$lambda$1(String str, String str2) {
        return android.support.v4.media.session.a.m("Starting download of url: ", str, " to ", str2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalHtmlUrlFromRemoteUrl$lambda$2(String str) {
        return AbstractC1484j.a("Could not download zip file to local storage. ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalHtmlUrlFromRemoteUrl$lambda$3(String str, String str2) {
        return android.support.v4.media.session.a.m("Html content zip downloaded. ", str, " to ", str2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalHtmlUrlFromRemoteUrl$lambda$4() {
        return "Error during the zip unpack.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getLocalHtmlUrlFromRemoteUrl$lambda$5(String str) {
        return AbstractC1476b.a("Html content zip unpacked to to ", str, '.');
    }

    public static final String replacePrefetchedUrlsWithLocalAssets(String originalString, Map<String, String> remoteToLocalAssetMap) {
        Intrinsics.checkNotNullParameter(originalString, "originalString");
        Intrinsics.checkNotNullParameter(remoteToLocalAssetMap, "remoteToLocalAssetMap");
        for (Map.Entry<String, String> entry : remoteToLocalAssetMap.entrySet()) {
            String value = entry.getValue();
            if (new File(value).exists()) {
                String key = entry.getKey();
                if (StringsKt.G(value, "ab_triggers", false)) {
                    String strA = AbstractC1484j.a("https://iamcache.braze/ab_triggers", (String) StringsKt__StringsKt.split$default(value, new String[]{"ab_triggers"}, false, 0, 6, null).get(1));
                    if (StringsKt.G(originalString, key, false)) {
                        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1481g(27, key, strA), 7, (Object) null);
                        originalString = D.o(originalString, key, strA, false);
                    }
                }
            } else {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new w(value, 5), 6, (Object) null);
            }
        }
        return originalString;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String replacePrefetchedUrlsWithLocalAssets$lambda$12(String str) {
        return AbstractC1484j.a("Cannot find local asset file at path: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String replacePrefetchedUrlsWithLocalAssets$lambda$13(String str, String str2) {
        return "Replacing remote url \"" + str + "\" with local uri \"" + str2 + '\"';
    }

    public static final boolean unpackZipIntoDirectory(String unpackDirectory, File zipFile) {
        Intrinsics.checkNotNullParameter(unpackDirectory, "unpackDirectory");
        Intrinsics.checkNotNullParameter(zipFile, "zipFile");
        if (StringsKt.O(unpackDirectory)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new v(13), 6, (Object) null);
            return false;
        }
        new File(unpackDirectory).mkdirs();
        try {
            J j = new J();
            ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipFile));
            try {
                for (ZipEntry nextEntry = zipInputStream.getNextEntry(); nextEntry != null; nextEntry = zipInputStream.getNextEntry()) {
                    String name = nextEntry.getName();
                    j.a = name;
                    Locale US = Locale.US;
                    Intrinsics.checkNotNullExpressionValue(US, "US");
                    String lowerCase = name.toLowerCase(US);
                    Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
                    if (!D.r(lowerCase, "__macosx", false)) {
                        try {
                            String strValidateChildFileExistsUnderParent = validateChildFileExistsUnderParent(unpackDirectory, unpackDirectory + '/' + ((String) j.a));
                            if (nextEntry.isDirectory()) {
                                new File(strValidateChildFileExistsUnderParent).mkdirs();
                            } else {
                                try {
                                    File parentFile = new File(strValidateChildFileExistsUnderParent).getParentFile();
                                    if (parentFile != null) {
                                        parentFile.mkdirs();
                                    }
                                } catch (Exception e) {
                                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new C1480f(j, 10), 4, (Object) null);
                                }
                                BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(strValidateChildFileExistsUnderParent));
                                try {
                                    AbstractC3332e.b(zipInputStream, bufferedOutputStream);
                                    bufferedOutputStream.close();
                                } catch (Throwable th) {
                                    try {
                                        throw th;
                                    } catch (Throwable th2) {
                                        AbstractC3336f.c(bufferedOutputStream, th);
                                        throw th2;
                                    }
                                }
                            }
                        } catch (Exception e2) {
                            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.E, (Throwable) e2, false, (Function0) new C1480f(j, 9), 4, (Object) null);
                        }
                    }
                    zipInputStream.closeEntry();
                }
                Unit unit = Unit.a;
                zipInputStream.close();
                return true;
            } finally {
            }
        } catch (Throwable th3) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.E, th3, false, (Function0) new C1277j(27, zipFile, unpackDirectory), 4, (Object) null);
            return false;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String unpackZipIntoDirectory$lambda$10$lambda$7(J j) {
        return "Error creating parent directory " + ((String) j.a);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String unpackZipIntoDirectory$lambda$10$lambda$9(J j) {
        return "Error unpacking zipEntry " + ((String) j.a);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String unpackZipIntoDirectory$lambda$11(File file, String str) {
        return "Error during unpack of zip file " + file.getAbsolutePath() + " to " + str + '.';
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String unpackZipIntoDirectory$lambda$6() {
        return "Unpack directory is blank. Zip file not unpacked.";
    }

    public static final String validateChildFileExistsUnderParent(String intendedParentDirectory, String childFilePath) throws IOException {
        Intrinsics.checkNotNullParameter(intendedParentDirectory, "intendedParentDirectory");
        Intrinsics.checkNotNullParameter(childFilePath, "childFilePath");
        String canonicalPath = new File(intendedParentDirectory).getCanonicalPath();
        String canonicalPath2 = new File(childFilePath).getCanonicalPath();
        Intrinsics.d(canonicalPath2);
        Intrinsics.d(canonicalPath);
        if (D.r(canonicalPath2, canonicalPath, false)) {
            return canonicalPath2;
        }
        throw new IllegalStateException(AbstractC0147y.g(AbstractC0147y.h("Invalid file with original path: ", childFilePath, " with canonical path: ", canonicalPath2, " does not exist under intended parent with  path: "), intendedParentDirectory, " and canonical path: ", canonicalPath));
    }
}
