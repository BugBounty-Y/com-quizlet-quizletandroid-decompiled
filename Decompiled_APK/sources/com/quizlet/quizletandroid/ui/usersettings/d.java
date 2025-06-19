package com.quizlet.quizletandroid.ui.usersettings;

import android.content.Context;
import com.google.android.datatransport.cct.internal.s;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.infra.legacysyncengine.tasks.parse.f;
import io.reactivex.rxjava3.core.o;

/* loaded from: classes3.dex */
public final class d {
    public final Context a;
    public final o b;
    public final o c;
    public final IQuizletApiClient d;
    public final s e;
    public final f f;
    public final UserInfoCache g;
    public final com.quizlet.db.token.a h;
    public final com.quizlet.infra.legacysyncengine.managers.d i;

    public d(Context context, o oVar, o oVar2, IQuizletApiClient iQuizletApiClient, s sVar, f fVar, UserInfoCache userInfoCache, com.quizlet.db.token.a aVar, com.quizlet.infra.legacysyncengine.managers.d dVar) {
        this.a = context;
        this.b = oVar;
        this.c = oVar2;
        this.d = iQuizletApiClient;
        this.e = sVar;
        this.f = fVar;
        this.g = userInfoCache;
        this.h = aVar;
        this.i = dVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:35:0x00c0  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00c5 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final io.reactivex.rxjava3.core.p a(android.graphics.Bitmap r8) throws java.lang.Throwable {
        /*
            r7 = this;
            r0 = 0
            java.util.UUID r1 = java.util.UUID.randomUUID()
            java.lang.String r1 = r1.toString()
            java.lang.String r2 = ".png"
            r3 = 0
            android.content.Context r4 = r7.a     // Catch: java.lang.Throwable -> La3 java.io.IOException -> La6
            java.io.File r4 = r4.getCacheDir()     // Catch: java.lang.Throwable -> La3 java.io.IOException -> La6
            java.io.File r1 = java.io.File.createTempFile(r1, r2, r4)     // Catch: java.lang.Throwable -> La3 java.io.IOException -> La6
            java.io.FileOutputStream r2 = new java.io.FileOutputStream     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La0
            r2.<init>(r1)     // Catch: java.lang.Throwable -> L9d java.io.IOException -> La0
            android.graphics.Bitmap$CompressFormat r3 = android.graphics.Bitmap.CompressFormat.PNG     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            r8.compress(r3, r0, r2)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            java.lang.String r8 = r1.getName()     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            java.lang.String r3 = "profile_img"
            java.lang.String r4 = "image/png"
            java.lang.String r5 = "filename"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r8, r5)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            java.lang.String r5 = "name"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r5)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            java.lang.String r5 = "mimeType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r5)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            java.lang.String r5 = "file"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r5)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            com.quizlet.data.interactor.set.c r5 = new com.quizlet.data.interactor.set.c     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            r5.<init>(r0)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            okhttp3.w r6 = okhttp3.y.f     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            r5.r(r6)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            java.util.regex.Pattern r6 = okhttp3.w.e     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            okhttp3.w r4 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2.d(r4)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            okhttp3.D r4 = okhttp3.F.c(r4, r1)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            r5.h(r3, r8, r4)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            okhttp3.y r8 = r5.k()     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            com.quizlet.api.IQuizletApiClient r3 = r7.d     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            io.reactivex.rxjava3.internal.operators.single.g r8 = r3.v(r8)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            com.quizlet.quizletandroid.ui.setcreation.imageupload.a r3 = new com.quizlet.quizletandroid.ui.setcreation.imageupload.a     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            r4 = 12
            r3.<init>(r4)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            io.reactivex.rxjava3.internal.operators.single.g r8 = r8.e(r3)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            io.reactivex.rxjava3.core.o r3 = r7.b     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            io.reactivex.rxjava3.internal.operators.single.k r8 = r8.l(r3)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            io.reactivex.rxjava3.core.o r3 = r7.c     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            io.reactivex.rxjava3.internal.operators.single.k r8 = r8.h(r3)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            com.quizlet.quizletandroid.ui.usersettings.c r3 = new com.quizlet.quizletandroid.ui.usersettings.c     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            r3.<init>(r7, r0)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            io.reactivex.rxjava3.internal.operators.single.d r0 = new io.reactivex.rxjava3.internal.operators.single.d     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            r4 = 2
            r0.<init>(r8, r3, r4)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            com.quizlet.quizletandroid.ui.setcreation.imageupload.a r8 = new com.quizlet.quizletandroid.ui.setcreation.imageupload.a     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            r3 = 13
            r8.<init>(r3)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            io.reactivex.rxjava3.internal.operators.single.g r8 = r0.e(r8)     // Catch: java.lang.Throwable -> L97 java.io.IOException -> L9a
            r1.deleteOnExit()
            r2.close()     // Catch: java.io.IOException -> L91
            return r8
        L91:
            r8 = move-exception
            io.reactivex.rxjava3.internal.operators.flowable.b r8 = io.reactivex.rxjava3.core.p.d(r8)
            return r8
        L97:
            r8 = move-exception
        L98:
            r3 = r1
            goto Lbe
        L9a:
            r8 = move-exception
        L9b:
            r3 = r1
            goto La8
        L9d:
            r8 = move-exception
            r2 = r3
            goto L98
        La0:
            r8 = move-exception
            r2 = r3
            goto L9b
        La3:
            r8 = move-exception
            r2 = r3
            goto Lbe
        La6:
            r8 = move-exception
            r2 = r3
        La8:
            io.reactivex.rxjava3.internal.operators.flowable.b r8 = io.reactivex.rxjava3.core.p.d(r8)     // Catch: java.lang.Throwable -> Lbd
            if (r3 == 0) goto Lb1
            r3.deleteOnExit()
        Lb1:
            if (r2 == 0) goto Lbc
            r2.close()     // Catch: java.io.IOException -> Lb7
            goto Lbc
        Lb7:
            r8 = move-exception
            io.reactivex.rxjava3.internal.operators.flowable.b r8 = io.reactivex.rxjava3.core.p.d(r8)
        Lbc:
            return r8
        Lbd:
            r8 = move-exception
        Lbe:
            if (r3 == 0) goto Lc3
            r3.deleteOnExit()
        Lc3:
            if (r2 == 0) goto Lcf
            r2.close()     // Catch: java.io.IOException -> Lc9
            goto Lcf
        Lc9:
            r8 = move-exception
            io.reactivex.rxjava3.internal.operators.flowable.b r8 = io.reactivex.rxjava3.core.p.d(r8)
            return r8
        Lcf:
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.usersettings.d.a(android.graphics.Bitmap):io.reactivex.rxjava3.core.p");
    }
}
