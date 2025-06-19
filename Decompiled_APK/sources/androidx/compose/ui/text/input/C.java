package androidx.compose.ui.text.input;

import android.content.Context;
import android.graphics.Typeface;
import android.os.Trace;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3170i6;
import com.google.android.gms.internal.mlkit_vision_barcode.X6;
import com.google.android.gms.internal.mlkit_vision_barcode.Z6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;
import java.lang.reflect.Method;
import java.nio.MappedByteBuffer;

/* loaded from: classes.dex */
public final /* synthetic */ class C implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void a() {
        androidx.emoji2.text.t tVar = (androidx.emoji2.text.t) this.b;
        synchronized (tVar.d) {
            try {
                if (tVar.h == null) {
                    return;
                }
                try {
                    androidx.core.provider.h hVarC = tVar.c();
                    int i = hVarC.e;
                    if (i == 2) {
                        synchronized (tVar.d) {
                        }
                    }
                    if (i != 0) {
                        throw new RuntimeException("fetchFonts result is not OK. (" + i + ")");
                    }
                    try {
                        Method method = androidx.core.os.h.b;
                        Trace.beginSection("EmojiCompat.FontRequestEmojiCompatConfig.buildTypeface");
                        com.quizlet.shared.usecase.srs.a aVar = tVar.c;
                        Context context = tVar.a;
                        aVar.getClass();
                        androidx.core.provider.h[] hVarArr = {hVarC};
                        AbstractC3161h6 abstractC3161h6 = androidx.core.graphics.h.a;
                        Trace.beginSection(AbstractC3359k2.f("TypefaceCompat.createFromFontInfo"));
                        try {
                            Typeface typefaceC = androidx.core.graphics.h.a.c(context, hVarArr, 0);
                            Trace.endSection();
                            MappedByteBuffer mappedByteBufferJ = AbstractC3170i6.j(tVar.a, hVarC.a);
                            if (mappedByteBufferJ == null || typefaceC == null) {
                                throw new RuntimeException("Unable to open file.");
                            }
                            try {
                                Trace.beginSection("EmojiCompat.MetadataRepo.create");
                                com.quizlet.data.repository.explanations.textbook.a aVar2 = new com.quizlet.data.repository.explanations.textbook.a(typefaceC, Z6.d(mappedByteBufferJ));
                                Trace.endSection();
                                synchronized (tVar.d) {
                                    try {
                                        X6 x6 = tVar.h;
                                        if (x6 != null) {
                                            x6.d(aVar2);
                                        }
                                    } finally {
                                    }
                                }
                                tVar.b();
                            } finally {
                                Method method2 = androidx.core.os.h.b;
                            }
                        } finally {
                            Trace.endSection();
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                } catch (Throwable th2) {
                    synchronized (tVar.d) {
                        try {
                            X6 x62 = tVar.h;
                            if (x62 != null) {
                                x62.c(th2);
                            }
                            tVar.b();
                        } finally {
                        }
                    }
                }
            } finally {
            }
        }
    }

    private final void b() {
        ((com.google.android.material.timepicker.e) this.b).p();
    }

    /* JADX WARN: Code restructure failed: missing block: B:229:0x04fd, code lost:
    
        r1 = r28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:230:0x04ff, code lost:
    
        if (r8 == 0) goto L448;
     */
    /* JADX WARN: Code restructure failed: missing block: B:231:0x0501, code lost:
    
        r1.put(r0, r13);
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:210:0x04c2  */
    /* JADX WARN: Removed duplicated region for block: B:255:0x05c7  */
    /* JADX WARN: Removed duplicated region for block: B:483:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r0v130, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r0v145, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r0v147, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r0v58 */
    /* JADX WARN: Type inference failed for: r0v59, types: [java.util.Collection] */
    /* JADX WARN: Type inference failed for: r2v4, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r3v51, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r4v3, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r6v0 */
    /* JADX WARN: Type inference failed for: r6v3 */
    /* JADX WARN: Type inference failed for: r6v4, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r8v20, types: [java.lang.Object, java.util.Map] */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 2470
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.text.input.C.run():void");
    }
}
