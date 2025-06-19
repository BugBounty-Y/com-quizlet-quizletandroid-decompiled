package androidx.emoji2.text;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.inputmethod.EditorInfo;
import androidx.collection.C0209g;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/* loaded from: classes.dex */
public final class j {
    public static final Object j = new Object();
    public static volatile j k;
    public final ReentrantReadWriteLock a;
    public final C0209g b;
    public volatile int c;
    public final Handler d;
    public final f e;
    public final i f;
    public final com.quizlet.shared.usecase.folderstudymaterials.d g;
    public final int h;
    public final d i;

    public j(u uVar) {
        ReentrantReadWriteLock reentrantReadWriteLock = new ReentrantReadWriteLock();
        this.a = reentrantReadWriteLock;
        this.c = 3;
        i iVar = (i) uVar.b;
        this.f = iVar;
        int i = uVar.a;
        this.h = i;
        this.i = (d) uVar.c;
        this.d = new Handler(Looper.getMainLooper());
        this.b = new C0209g(0);
        this.g = new com.quizlet.shared.usecase.folderstudymaterials.d(3);
        f fVar = new f(this);
        this.e = fVar;
        reentrantReadWriteLock.writeLock().lock();
        if (i == 0) {
            try {
                this.c = 0;
            } catch (Throwable th) {
                this.a.writeLock().unlock();
                throw th;
            }
        }
        reentrantReadWriteLock.writeLock().unlock();
        if (b() == 0) {
            try {
                iVar.a(new e(fVar));
            } catch (Throwable th2) {
                e(th2);
            }
        }
    }

    public static j a() {
        j jVar;
        synchronized (j) {
            jVar = k;
            AbstractC3242q6.h("EmojiCompat is not initialized.\n\nYou must initialize EmojiCompat prior to referencing the EmojiCompat instance.\n\nThe most likely cause of this error is disabling the EmojiCompatInitializer\neither explicitly in AndroidManifest.xml, or by including\nandroidx.emoji2:emoji2-bundled.\n\nAutomatic initialization is typically performed by EmojiCompatInitializer. If\nyou are not expecting to initialize EmojiCompat manually in your application,\nplease check to ensure it has not been removed from your APK's manifest. You can\ndo this in Android Studio using Build > Analyze APK.\n\nIn the APK Analyzer, ensure that the startup entry for\nEmojiCompatInitializer and InitializationProvider is present in\n AndroidManifest.xml. If it is missing or contains tools:node=\"remove\", and you\nintend to use automatic configuration, verify:\n\n  1. Your application does not include emoji2-bundled\n  2. All modules do not contain an exclusion manifest rule for\n     EmojiCompatInitializer or InitializationProvider. For more information\n     about manifest exclusions see the documentation for the androidx startup\n     library.\n\nIf you intend to use emoji2-bundled, please call EmojiCompat.init. You can\nlearn more in the documentation for BundledEmojiCompatConfig.\n\nIf you intended to perform manual configuration, it is recommended that you call\nEmojiCompat.init immediately on application startup.\n\nIf you still cannot resolve this issue, please open a bug with your specific\nconfiguration to help improve error message.", jVar != null);
        }
        return jVar;
    }

    public static boolean c() {
        return k != null;
    }

    public final int b() {
        this.a.readLock().lock();
        try {
            return this.c;
        } finally {
            this.a.readLock().unlock();
        }
    }

    public final void d() {
        AbstractC3242q6.h("Set metadataLoadStrategy to LOAD_STRATEGY_MANUAL to execute manual loading", this.h == 1);
        if (b() == 1) {
            return;
        }
        this.a.writeLock().lock();
        try {
            if (this.c == 0) {
                return;
            }
            this.c = 0;
            this.a.writeLock().unlock();
            f fVar = this.e;
            j jVar = (j) fVar.b;
            try {
                jVar.f.a(new e(fVar));
            } catch (Throwable th) {
                jVar.e(th);
            }
        } finally {
            this.a.writeLock().unlock();
        }
    }

    public final void e(Throwable th) {
        ArrayList arrayList = new ArrayList();
        this.a.writeLock().lock();
        try {
            this.c = 2;
            arrayList.addAll(this.b);
            this.b.clear();
            this.a.writeLock().unlock();
            this.d.post(new androidx.core.provider.a(arrayList, this.c, th));
        } catch (Throwable th2) {
            this.a.writeLock().unlock();
            throw th2;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x009b A[Catch: all -> 0x008e, TRY_ENTER, TryCatch #2 {all -> 0x008e, blocks: (B:35:0x0066, B:38:0x006b, B:40:0x006f, B:42:0x007c, B:49:0x009b, B:51:0x00a5, B:53:0x00a8, B:55:0x00ab, B:57:0x00bb, B:58:0x00be), top: B:94:0x0066 }] */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00ab A[Catch: all -> 0x008e, TryCatch #2 {all -> 0x008e, blocks: (B:35:0x0066, B:38:0x006b, B:40:0x006f, B:42:0x007c, B:49:0x009b, B:51:0x00a5, B:53:0x00a8, B:55:0x00ab, B:57:0x00bb, B:58:0x00be), top: B:94:0x0066 }] */
    /* JADX WARN: Removed duplicated region for block: B:62:0x00cd A[Catch: all -> 0x0103, TRY_ENTER, TryCatch #1 {all -> 0x0103, blocks: (B:62:0x00cd, B:65:0x00d5, B:47:0x0091), top: B:92:0x0091 }] */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00d3  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x010b  */
    /* JADX WARN: Removed duplicated region for block: B:97:? A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:99:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.CharSequence f(int r12, int r13, int r14, java.lang.CharSequence r15) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 291
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.emoji2.text.j.f(int, int, int, java.lang.CharSequence):java.lang.CharSequence");
    }

    public final void g(h hVar) {
        AbstractC3242q6.g(hVar, "initCallback cannot be null");
        this.a.writeLock().lock();
        try {
            if (this.c == 1 || this.c == 2) {
                this.d.post(new androidx.core.provider.a(Arrays.asList(hVar), this.c, (Throwable) null));
            } else {
                this.b.add(hVar);
            }
            this.a.writeLock().unlock();
        } catch (Throwable th) {
            this.a.writeLock().unlock();
            throw th;
        }
    }

    public final void h(EditorInfo editorInfo) {
        if (b() != 1 || editorInfo == null) {
            return;
        }
        if (editorInfo.extras == null) {
            editorInfo.extras = new Bundle();
        }
        f fVar = this.e;
        fVar.getClass();
        Bundle bundle = editorInfo.extras;
        androidx.emoji2.text.flatbuffer.b bVar = (androidx.emoji2.text.flatbuffer.b) ((com.quizlet.data.repository.explanations.textbook.a) fVar.c).a;
        int iA = bVar.a(4);
        bundle.putInt("android.support.text.emoji.emojiCompat_metadataVersion", iA != 0 ? ((ByteBuffer) bVar.d).getInt(iA + bVar.a) : 0);
        Bundle bundle2 = editorInfo.extras;
        ((j) fVar.b).getClass();
        bundle2.putBoolean("android.support.text.emoji.emojiCompat_replaceAll", false);
    }
}
