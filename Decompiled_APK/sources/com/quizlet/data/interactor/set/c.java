package com.quizlet.data.interactor.set;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Build;
import android.view.ViewGroup;
import android.view.WindowManager;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.text.C0494i0;
import androidx.lifecycle.C;
import assistantMode.refactored.types.flashcards.FlashcardsModeSettings;
import assistantMode.refactored.types.flashcards.f;
import com.braze.C1510p;
import com.bumptech.glide.load.ImageHeaderParser$ImageType;
import com.bumptech.glide.load.d;
import com.bumptech.glide.load.resource.bitmap.v;
import com.bumptech.glide.load.resource.bitmap.w;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3355j2;
import com.google.android.gms.internal.mlkit_vision_camera.C3319a2;
import com.google.android.gms.internal.mlkit_vision_camera.C3323b2;
import com.google.android.gms.internal.mlkit_vision_camera.C3414y2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.N4;
import com.google.android.gms.measurement.internal.K;
import com.google.android.gms.measurement.internal.r1;
import com.google.firebase.encoders.EncodingException;
import com.quizlet.data.model.U1;
import com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.l;
import com.quizlet.quizletandroid.C4624g;
import com.quizlet.quizletandroid.t;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.ads.E;
import com.quizlet.quizletandroid.ui.common.ads.prebid.m;
import io.reactivex.rxjava3.core.g;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.observable.C4896o;
import io.reactivex.rxjava3.internal.operators.observable.C4905y;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.F;
import okhttp3.x;
import okhttp3.y;
import okio.k;

/* loaded from: classes2.dex */
public final class c implements v, K, h {
    public Object a;
    public Object b;
    public Object c;

    public c(r1 r1Var, String str, ArrayList arrayList) {
        this.a = str;
        this.b = arrayList;
        this.c = r1Var;
    }

    public static final Object g(c cVar, C c, WindowManager windowManager, int i, com.quizlet.features.setpage.shareset.a aVar, ViewGroup viewGroup, boolean z, Function0 function0, Function1 function1, i iVar) {
        if (z) {
            m mVar = (m) ((t) cVar.b).get();
            c.a(mVar);
            String str = aVar.a;
            U1 u1 = aVar.b;
            Object objB = m.b(mVar, i, str, viewGroup, windowManager, u1 != null ? u1.a() : null, new com.quizlet.features.setpage.composable.a(17, function0), new l(26, function1), iVar, 16);
            kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
            if (objB != aVar2) {
                objB = Unit.a;
            }
            return objB == aVar2 ? objB : Unit.a;
        }
        E e = (E) ((t) cVar.a).get();
        c.a(e);
        String str2 = aVar.a;
        U1 u12 = aVar.b;
        Object objB2 = N4.a(e, i, str2, viewGroup, windowManager, u12 != null ? u12.a() : null, 16).b(new C0494i0(19, function0, function1), iVar);
        kotlin.coroutines.intrinsics.a aVar3 = kotlin.coroutines.intrinsics.a.a;
        if (objB2 != aVar3) {
            objB2 = Unit.a;
        }
        return objB2 == aVar3 ? objB2 : Unit.a;
    }

    public static void p() {
        if (Build.VERSION.SDK_INT >= 29) {
            throw new UnsupportedClassVersionError("This function can only be used for API Level < 29.");
        }
    }

    @Override // com.google.android.gms.measurement.internal.K
    public void a(String str, int i, IOException iOException, byte[] bArr, Map map) {
        ((r1) this.c).u(true, i, iOException, bArr, (String) this.a, (ArrayList) this.b);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        File cacheFile = (File) obj;
        Intrinsics.checkNotNullParameter(cacheFile, "cacheFile");
        boolean zExists = cacheFile.exists();
        String str = (String) this.a;
        if (zExists && cacheFile.length() == 0) {
            timber.log.c.a.g(AbstractC0147y.e("Deleting ", cacheFile.getPath(), " from ", str, " because it's size 0"), new Object[0]);
            cacheFile.delete();
        }
        return cacheFile.exists() ? g.c(cacheFile) : com.quizlet.quizletandroid.managers.audio.g.c((com.quizlet.quizletandroid.managers.audio.g) this.b, str, cacheFile, (com.quizlet.quizletandroid.data.cache.a) this.c);
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x014e  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x01a2  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x01ce  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0200  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0203 A[PHI: r5
  0x0203: PHI (r5v8 java.lang.Process) = (r5v7 java.lang.Process), (r5v13 java.lang.Process) binds: [B:57:0x0206, B:53:0x01fe] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:62:0x0210 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:65:0x021a  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x023c A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:70:0x025e  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x026d A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0288  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x01e1 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.perimeterx.mobile_sdk.detections.device.a b(android.app.Application r43) {
        /*
            Method dump skipped, instructions count: 720
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.set.c.b(android.app.Application):com.perimeterx.mobile_sdk.detections.device.a");
    }

    @Override // com.bumptech.glide.load.resource.bitmap.v
    public int c() throws Throwable {
        w wVar;
        com.bumptech.glide.load.data.i iVar = (com.bumptech.glide.load.data.i) this.c;
        androidx.compose.foundation.lazy.grid.m mVar = (androidx.compose.foundation.lazy.grid.m) this.a;
        ArrayList arrayList = (ArrayList) this.b;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            d dVar = (d) arrayList.get(i);
            w wVar2 = null;
            try {
                wVar = new w(new FileInputStream(iVar.c().getFileDescriptor()), mVar);
            } catch (Throwable th) {
                th = th;
            }
            try {
                int iB = dVar.b(wVar, mVar);
                wVar.d();
                iVar.c();
                if (iB != -1) {
                    return iB;
                }
            } catch (Throwable th2) {
                th = th2;
                wVar2 = wVar;
                if (wVar2 != null) {
                    wVar2.d();
                }
                iVar.c();
                throw th;
            }
        }
        return -1;
    }

    @Override // com.bumptech.glide.load.resource.bitmap.v
    public Bitmap d(BitmapFactory.Options options) {
        return BitmapFactory.decodeFileDescriptor(((com.bumptech.glide.load.data.i) this.c).c().getFileDescriptor(), null, options);
    }

    @Override // com.bumptech.glide.load.resource.bitmap.v
    public void e() {
    }

    @Override // com.bumptech.glide.load.resource.bitmap.v
    public ImageHeaderParser$ImageType f() throws Throwable {
        w wVar;
        com.bumptech.glide.load.data.i iVar = (com.bumptech.glide.load.data.i) this.c;
        androidx.compose.foundation.lazy.grid.m mVar = (androidx.compose.foundation.lazy.grid.m) this.a;
        ArrayList arrayList = (ArrayList) this.b;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            d dVar = (d) arrayList.get(i);
            w wVar2 = null;
            try {
                wVar = new w(new FileInputStream(iVar.c().getFileDescriptor()), mVar);
            } catch (Throwable th) {
                th = th;
            }
            try {
                ImageHeaderParser$ImageType imageHeaderParser$ImageTypeC = dVar.c(wVar);
                wVar.d();
                iVar.c();
                if (imageHeaderParser$ImageTypeC != ImageHeaderParser$ImageType.UNKNOWN) {
                    return imageHeaderParser$ImageTypeC;
                }
            } catch (Throwable th2) {
                th = th2;
                wVar2 = wVar;
                if (wVar2 != null) {
                    wVar2.d();
                }
                iVar.c();
                throw th;
            }
        }
        return ImageHeaderParser$ImageType.UNKNOWN;
    }

    public void h(String name, String str, F body) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(body, "body");
        i(AbstractC3355j2.b(name, str, body));
    }

    public void i(x part) {
        Intrinsics.checkNotNullParameter(part, "part");
        ((ArrayList) this.c).add(part);
    }

    public f j() {
        assistantMode.refactored.studyEngines.b bVar;
        assistantMode.refactored.studyEngines.b bVar2 = (assistantMode.refactored.studyEngines.b) this.c;
        if (bVar2.l) {
            if (!CollectionsKt.w0(bVar2.n.a).isEmpty()) {
                throw new IllegalStateException("Stored Answers should be retrieved before starting a new round");
            }
            ArrayList arrayList = bVar2.d;
            boolean zIsEmpty = arrayList.isEmpty();
            int i = bVar2.h;
            List list = bVar2.e;
            if (!zIsEmpty) {
                List list2 = bVar2.c;
                if (list2.size() < bVar2.p) {
                    throw new IllegalStateException("Cannot begin round while previous round is still in progress");
                }
                FlashcardsModeSettings flashcardsModeSettings = bVar2.b;
                List list3 = bVar2.g;
                bVar = new assistantMode.refactored.studyEngines.b(bVar2.a, flashcardsModeSettings, CollectionsKt.y0(list2), CollectionsKt.y0(arrayList), CollectionsKt.y0(list), list3, i + 1, bVar2.j, bVar2.k, 288);
            } else {
                if (list.isEmpty()) {
                    throw new IllegalStateException("Cannot begin round with no flashcards");
                }
                FlashcardsModeSettings flashcardsModeSettings2 = bVar2.b;
                List list4 = bVar2.g;
                bVar = new assistantMode.refactored.studyEngines.b(bVar2.a, flashcardsModeSettings2, null, CollectionsKt.y0(list), null, list4, i + 1, bVar2.j, bVar2.k, 308);
            }
            this.c = bVar;
        }
        assistantMode.refactored.studyEngines.b bVar3 = (assistantMode.refactored.studyEngines.b) this.c;
        bVar3.l = true;
        return bVar3.b();
    }

    public y k() {
        ArrayList arrayList = (ArrayList) this.c;
        if (arrayList.isEmpty()) {
            throw new IllegalStateException("Multipart body must have at least one part.");
        }
        return new y((k) this.a, (okhttp3.w) this.b, okhttp3.internal.b.y(arrayList));
    }

    public io.reactivex.rxjava3.core.i l(long j, p stopToken) {
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        Long lValueOf = Long.valueOf(j);
        com.quizlet.cache.a aVar = (com.quizlet.cache.a) this.c;
        io.reactivex.rxjava3.core.i iVar = (io.reactivex.rxjava3.core.i) aVar.get(lValueOf);
        if (iVar != null) {
            return iVar;
        }
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        C4905y c4905y = new C4905y(new C4896o(new io.reactivex.rxjava3.internal.operators.mixed.b(((androidx.work.impl.model.c) this.b).b(stopToken, new C1510p(this, j, 17)))), new com.quizlet.data.interactor.base.a(aVar, lValueOf, 1), 1);
        Intrinsics.checkNotNullExpressionValue(c4905y, "doFinally(...)");
        aVar.a(lValueOf, c4905y);
        return c4905y;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /* JADX WARN: Type inference failed for: r11v3, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r11v5, types: [java.util.ArrayList] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object m(long r10, long r12, com.quizlet.data.model.J0 r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            r9 = this;
            boolean r0 = r15 instanceof com.quizlet.remote.model.selectedterm.e
            if (r0 == 0) goto L14
            r0 = r15
            com.quizlet.remote.model.selectedterm.e r0 = (com.quizlet.remote.model.selectedterm.e) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.m = r1
        L12:
            r7 = r0
            goto L1a
        L14:
            com.quizlet.remote.model.selectedterm.e r0 = new com.quizlet.remote.model.selectedterm.e
            r0.<init>(r9, r15)
            goto L12
        L1a:
            java.lang.Object r15 = r7.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.m
            r8 = 0
            r2 = 1
            if (r1 == 0) goto L38
            if (r1 != r2) goto L30
            com.quizlet.data.interactor.set.c r10 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r15)
            kotlin.r r15 = (kotlin.r) r15
            java.lang.Object r11 = r15.a
            goto L57
        L30:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            if (r14 == 0) goto L43
            com.quizlet.remote.model.base.PagingInfo r14 = com.quizlet.remote.model.base.b.b(r14)
            r6 = r14
            goto L44
        L43:
            r6 = r8
        L44:
            r7.j = r9
            r7.m = r2
            java.lang.Object r14 = r9.a
            r1 = r14
            com.quizlet.quizletandroid.k r1 = (com.quizlet.quizletandroid.k) r1
            r2 = r10
            r4 = r12
            java.lang.Object r11 = r1.l(r2, r4, r6, r7)
            if (r11 != r0) goto L56
            return r0
        L56:
            r10 = r9
        L57:
            kotlin.p r12 = kotlin.r.b
            boolean r12 = r11 instanceof kotlin.q
            if (r12 != 0) goto Laa
            com.quizlet.remote.model.selectedterm.SelectedTermResponse r11 = (com.quizlet.remote.model.selectedterm.SelectedTermResponse) r11
            com.quizlet.remote.model.base.PagingInfo r12 = r11.a
            if (r12 == 0) goto L69
            java.lang.Object r13 = r10.c
            com.quizlet.data.model.J0 r8 = com.quizlet.remote.model.base.b.a(r12)
        L69:
            java.lang.Object r10 = r10.b
            com.quizlet.quizletandroid.ui.login.di.a r10 = (com.quizlet.quizletandroid.ui.login.di.a) r10
            java.lang.String r12 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r11, r12)
            java.lang.String r12 = "mapper"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r12)
            com.quizlet.remote.model.selectedterm.SelectedTermModels r10 = r11.d
            if (r10 == 0) goto La2
            java.util.List r10 = r10.a
            if (r10 == 0) goto La2
            java.util.ArrayList r11 = new java.util.ArrayList
            r12 = 10
            int r12 = kotlin.collections.C.q(r10, r12)
            r11.<init>(r12)
            java.util.Iterator r10 = r10.iterator()
        L8e:
            boolean r12 = r10.hasNext()
            if (r12 == 0) goto La4
            java.lang.Object r12 = r10.next()
            com.quizlet.remote.model.selectedterm.a r12 = (com.quizlet.remote.model.selectedterm.a) r12
            com.quizlet.data.model.D1 r12 = com.quizlet.quizletandroid.ui.login.di.a.a(r12)
            r11.add(r12)
            goto L8e
        La2:
            kotlin.collections.K r11 = kotlin.collections.K.a
        La4:
            com.quizlet.data.model.N r10 = new com.quizlet.data.model.N
            r10.<init>(r11, r8)
            return r10
        Laa:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.set.c.m(long, long, com.quizlet.data.model.J0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:102:0x024e  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0250  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x0282  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x02a7  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x02b5  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x02f6  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x02fa  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x0363  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x0365  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x0393  */
    /* JADX WARN: Removed duplicated region for block: B:156:0x03c2  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x03db  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x03fe  */
    /* JADX WARN: Removed duplicated region for block: B:169:0x040f  */
    /* JADX WARN: Removed duplicated region for block: B:170:0x0411  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x0438  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x0446  */
    /* JADX WARN: Removed duplicated region for block: B:180:0x0448  */
    /* JADX WARN: Removed duplicated region for block: B:186:0x0472  */
    /* JADX WARN: Removed duplicated region for block: B:189:0x0480  */
    /* JADX WARN: Removed duplicated region for block: B:190:0x0482  */
    /* JADX WARN: Removed duplicated region for block: B:194:0x04a1  */
    /* JADX WARN: Removed duplicated region for block: B:197:0x04ad  */
    /* JADX WARN: Removed duplicated region for block: B:200:0x04be  */
    /* JADX WARN: Removed duplicated region for block: B:203:0x04c8  */
    /* JADX WARN: Removed duplicated region for block: B:211:0x04f5  */
    /* JADX WARN: Removed duplicated region for block: B:214:0x0501  */
    /* JADX WARN: Removed duplicated region for block: B:217:0x050b  */
    /* JADX WARN: Removed duplicated region for block: B:221:0x0521  */
    /* JADX WARN: Removed duplicated region for block: B:243:0x020c A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:245:0x03a3 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:249:0x0537 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00d4  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0198  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x01aa  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x01ca  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x01fe  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x022e  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0242  */
    /* JADX WARN: Type inference failed for: r0v115 */
    /* JADX WARN: Type inference failed for: r0v174 */
    /* JADX WARN: Type inference failed for: r0v175 */
    /* JADX WARN: Type inference failed for: r0v92, types: [int] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean n() throws android.content.pm.PackageManager.NameNotFoundException {
        /*
            Method dump skipped, instructions count: 1457
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.set.c.n():boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object o(long r11, kotlin.coroutines.jvm.internal.c r13) {
        /*
            r10 = this;
            boolean r0 = r13 instanceof com.quizlet.features.infra.basestudy.usecase.d
            if (r0 == 0) goto L14
            r0 = r13
            com.quizlet.features.infra.basestudy.usecase.d r0 = (com.quizlet.features.infra.basestudy.usecase.d) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.p = r1
        L12:
            r7 = r0
            goto L1a
        L14:
            com.quizlet.features.infra.basestudy.usecase.d r0 = new com.quizlet.features.infra.basestudy.usecase.d
            r0.<init>(r10, r13)
            goto L12
        L1a:
            java.lang.Object r13 = r7.n
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.p
            r2 = 2
            r3 = 1
            if (r1 == 0) goto L43
            if (r1 == r3) goto L34
            if (r1 != r2) goto L2c
            androidx.glance.appwidget.protobuf.Z.e(r13)
            return r13
        L2c:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L34:
            long r11 = r7.m
            com.quizlet.generated.enums.P r1 = r7.l
            java.lang.Long r3 = r7.k
            com.quizlet.data.interactor.metering.b r4 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            r5 = r1
            r1 = r4
            r4 = r3
            goto L77
        L43:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            java.lang.Object r13 = r10.b
            com.quizlet.infra.legacysyncengine.managers.d r13 = (com.quizlet.infra.legacysyncengine.managers.d) r13
            com.quizlet.db.data.caches.UserInfoCache r13 = r13.e
            long r4 = r13.getPersonId()
            java.lang.Long r13 = new java.lang.Long
            r13.<init>(r11)
            com.quizlet.generated.enums.P r1 = com.quizlet.generated.enums.P.TEST_SUBMISSION
            java.lang.Object r11 = r10.a
            com.quizlet.data.interactor.metering.b r11 = (com.quizlet.data.interactor.metering.b) r11
            r7.j = r11
            r7.k = r13
            r7.l = r1
            r7.m = r4
            r7.p = r3
            java.lang.Object r12 = r10.c
            androidx.work.impl.model.c r12 = (androidx.work.impl.model.c) r12
            java.lang.Object r12 = androidx.camera.core.AbstractC0151c.a(r12, r7)
            if (r12 != r0) goto L70
            goto L8d
        L70:
            r8 = r1
            r1 = r11
            r9 = r13
            r13 = r12
            r11 = r4
            r4 = r9
            r5 = r8
        L77:
            java.lang.Boolean r13 = (java.lang.Boolean) r13
            boolean r6 = r13.booleanValue()
            r13 = 0
            r7.j = r13
            r7.k = r13
            r7.l = r13
            r7.p = r2
            r2 = r11
            java.io.Serializable r11 = r1.a(r2, r4, r5, r6, r7)
            if (r11 != r0) goto L8e
        L8d:
            return r0
        L8e:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.set.c.o(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0015  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable q(long r15, long r17, long r19, int r21, boolean r22, kotlin.coroutines.jvm.internal.c r23) {
        /*
            r14 = this;
            r0 = r23
            boolean r1 = r0 instanceof com.quizlet.remote.model.selectedterm.f
            if (r1 == 0) goto L15
            r1 = r0
            com.quizlet.remote.model.selectedterm.f r1 = (com.quizlet.remote.model.selectedterm.f) r1
            int r2 = r1.m
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L15
            int r2 = r2 - r3
            r1.m = r2
            goto L1a
        L15:
            com.quizlet.remote.model.selectedterm.f r1 = new com.quizlet.remote.model.selectedterm.f
            r1.<init>(r14, r0)
        L1a:
            java.lang.Object r0 = r1.k
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            int r3 = r1.m
            r4 = 2
            r5 = 1
            if (r3 == 0) goto L3c
            if (r3 == r5) goto L36
            if (r3 != r4) goto L2e
            com.quizlet.data.interactor.set.c r1 = r1.j
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L82
        L2e:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L36:
            com.quizlet.data.interactor.set.c r1 = r1.j
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L6a
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.remote.model.selectedterm.SelectedTermRequest r6 = new com.quizlet.remote.model.selectedterm.SelectedTermRequest
            r7 = r15
            r9 = r17
            r12 = r19
            r11 = r21
            r6.<init>(r7, r9, r11, r12)
            java.lang.Object r0 = r14.a
            com.quizlet.quizletandroid.k r0 = (com.quizlet.quizletandroid.k) r0
            java.lang.Object r0 = r0.b
            com.quizlet.remote.service.z r0 = (com.quizlet.remote.service.z) r0
            if (r22 == 0) goto L6d
            r1.j = r14
            r1.m = r5
            com.quizlet.remote.model.base.ApiPostBody r3 = new com.quizlet.remote.model.base.ApiPostBody
            java.util.List r4 = kotlin.collections.A.b(r6)
            r3.<init>(r4)
            java.lang.Object r0 = r0.a(r3, r1)
            if (r0 != r2) goto L69
            goto L80
        L69:
            r1 = r14
        L6a:
            com.quizlet.remote.model.base.ApiThreeWrapper r0 = (com.quizlet.remote.model.base.ApiThreeWrapper) r0
            goto L84
        L6d:
            r1.j = r14
            r1.m = r4
            com.quizlet.remote.model.base.ApiPostBody r3 = new com.quizlet.remote.model.base.ApiPostBody
            java.util.List r4 = kotlin.collections.A.b(r6)
            r3.<init>(r4)
            java.lang.Object r0 = r0.c(r3, r1)
            if (r0 != r2) goto L81
        L80:
            return r2
        L81:
            r1 = r14
        L82:
            com.quizlet.remote.model.base.ApiThreeWrapper r0 = (com.quizlet.remote.model.base.ApiThreeWrapper) r0
        L84:
            java.lang.Object r1 = r1.b
            com.quizlet.quizletandroid.ui.login.di.a r1 = (com.quizlet.quizletandroid.ui.login.di.a) r1
            java.lang.String r2 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            java.lang.String r2 = "mapper"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r2)
            com.quizlet.remote.model.base.ApiResponse r0 = r0.a()
            com.quizlet.remote.model.selectedterm.SelectedTermResponse r0 = (com.quizlet.remote.model.selectedterm.SelectedTermResponse) r0
            if (r0 == 0) goto Lc6
            com.quizlet.remote.model.selectedterm.SelectedTermModels r0 = r0.d
            if (r0 == 0) goto Lc6
            java.util.List r0 = r0.a
            if (r0 == 0) goto Lc6
            java.util.ArrayList r1 = new java.util.ArrayList
            r2 = 10
            int r2 = kotlin.collections.C.q(r0, r2)
            r1.<init>(r2)
            java.util.Iterator r0 = r0.iterator()
        Lb1:
            boolean r2 = r0.hasNext()
            if (r2 == 0) goto Lc5
            java.lang.Object r2 = r0.next()
            com.quizlet.remote.model.selectedterm.a r2 = (com.quizlet.remote.model.selectedterm.a) r2
            com.quizlet.data.model.D1 r2 = com.quizlet.quizletandroid.ui.login.di.a.a(r2)
            r1.add(r2)
            goto Lb1
        Lc5:
            return r1
        Lc6:
            kotlin.collections.K r0 = kotlin.collections.K.a
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.set.c.q(long, long, long, int, boolean, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public void r(okhttp3.w type) {
        Intrinsics.checkNotNullParameter(type, "type");
        if (Intrinsics.b(type.b, "multipart")) {
            this.b = type;
        } else {
            throw new IllegalArgumentException(("multipart != " + type).toString());
        }
    }

    public byte[] s(C3323b2 c3323b2) {
        C3414y2 c3414y2;
        com.google.firebase.encoders.c cVar;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            HashMap map = (HashMap) this.a;
            c3414y2 = new C3414y2(byteArrayOutputStream, map, (HashMap) this.b, (C3319a2) this.c);
            cVar = (com.google.firebase.encoders.c) map.get(C3323b2.class);
        } catch (IOException unused) {
        }
        if (cVar == null) {
            throw new EncodingException("No encoder for ".concat(String.valueOf(C3323b2.class)));
        }
        cVar.a(c3323b2, c3414y2);
        return byteArrayOutputStream.toByteArray();
    }

    public /* synthetic */ c(Object obj, Object obj2, Object obj3) {
        this.a = obj;
        this.b = obj2;
        this.c = obj3;
    }

    public c(com.perimeterx.mobile_sdk.session.m mVar, androidx.camera.camera2.internal.compat.workaround.a policy) {
        Intrinsics.checkNotNullParameter(policy, "policy");
        this.c = new com.google.android.gms.ads.internal.util.E(5);
        this.a = mVar;
        this.b = policy;
    }

    public c(com.quizlet.data.interactor.metering.b getMeteringInfoUseCase, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, androidx.work.impl.model.c userProperties) {
        Intrinsics.checkNotNullParameter(getMeteringInfoUseCase, "getMeteringInfoUseCase");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        this.a = getMeteringInfoUseCase;
        this.b = loggedInUserManager;
        this.c = userProperties;
    }

    public c(int i) {
        String boundary = UUID.randomUUID().toString();
        Intrinsics.checkNotNullExpressionValue(boundary, "randomUUID().toString()");
        Intrinsics.checkNotNullParameter(boundary, "boundary");
        k kVar = k.d;
        this.a = com.quizlet.quizletandroid.ui.common.images.capture.b.i(boundary);
        this.b = y.e;
        this.c = new ArrayList();
    }

    public c(u uVar, C4624g c4624g) {
        this.a = uVar;
        this.b = c4624g;
    }
}
