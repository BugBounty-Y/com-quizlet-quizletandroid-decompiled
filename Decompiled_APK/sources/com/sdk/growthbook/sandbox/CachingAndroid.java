package com.sdk.growthbook.sandbox;

import android.content.Context;
import android.support.v4.media.session.a;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import com.google.android.gms.internal.mlkit_vision_camera.Y1;
import com.quizlet.qutils.android.f;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.io.i;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.text.D;
import kotlin.text.StringsKt;
import kotlinx.serialization.json.c;
import kotlinx.serialization.json.g;
import kotlinx.serialization.json.k;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class CachingAndroid implements CachingLayer {

    @NotNull
    public static final Companion Companion = new Companion(null);
    private static File filesDir;

    @NotNull
    private final c json = Y1.c(new f(28));

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void consumeContext(@NotNull Context context) {
            Intrinsics.checkNotNullParameter(context, "context");
            setFilesDir$GrowthBook_release(context.getFilesDir());
        }

        public final File getFilesDir$GrowthBook_release() {
            return CachingAndroid.filesDir;
        }

        public final void setFilesDir$GrowthBook_release(File file) {
            CachingAndroid.filesDir = file;
        }

        private Companion() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit json$lambda$0(g Json) {
        Intrinsics.checkNotNullParameter(Json, "$this$Json");
        Json.e = true;
        Json.d = true;
        Json.c = true;
        return Unit.a;
    }

    @Override // com.sdk.growthbook.sandbox.CachingLayer
    public k getContent(@NotNull String fileName) throws IOException {
        Intrinsics.checkNotNullParameter(fileName, "fileName");
        File targetFile = getTargetFile(fileName);
        if (targetFile == null || !targetFile.exists()) {
            return null;
        }
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(targetFile), Charsets.UTF_8), 8192);
        try {
            String strB = AbstractC3340g.b(bufferedReader);
            bufferedReader.close();
            return (k) this.json.b(strB, k.Companion.serializer());
        } catch (Throwable th) {
            try {
                throw th;
            } catch (Throwable th2) {
                AbstractC3336f.c(bufferedReader, th);
                throw th2;
            }
        }
    }

    public final File getTargetFile(@NotNull String fileName) {
        Intrinsics.checkNotNullParameter(fileName, "fileName");
        if (filesDir == null) {
            return null;
        }
        File file = new File(filesDir, "GrowthBook-KMM");
        file.mkdirs();
        if (D.k(fileName, ".txt", true)) {
            fileName = StringsKt.U(fileName, ".txt");
        }
        return new File(file, a.k(fileName, ".txt"));
    }

    @Override // com.sdk.growthbook.sandbox.CachingLayer
    public void saveContent(@NotNull String fileName, @NotNull k content) throws IOException {
        Intrinsics.checkNotNullParameter(fileName, "fileName");
        Intrinsics.checkNotNullParameter(content, "content");
        File targetFile = getTargetFile(fileName);
        if (targetFile == null) {
            return;
        }
        if (targetFile.exists()) {
            targetFile.delete();
        }
        targetFile.createNewFile();
        String text = this.json.c(k.Companion.serializer(), content);
        Charset charset = Charsets.UTF_8;
        Intrinsics.checkNotNullParameter(targetFile, "<this>");
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(charset, "charset");
        FileOutputStream fileOutputStream = new FileOutputStream(targetFile, true);
        try {
            i.c(fileOutputStream, text, charset);
            Unit unit = Unit.a;
            fileOutputStream.close();
        } finally {
        }
    }
}
