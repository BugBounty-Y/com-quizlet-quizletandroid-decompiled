package com.quizlet.data.repository.activitycenter;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Rect;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import androidx.activity.r;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.camera.camera2.internal.compat.q;
import androidx.camera.camera2.internal.f0;
import androidx.camera.camera2.internal.p0;
import androidx.camera.core.impl.InterfaceC0159a0;
import androidx.camera.core.impl.InterfaceC0161b0;
import androidx.camera.core.impl.U;
import androidx.collection.G;
import androidx.collection.I;
import androidx.compose.foundation.gestures.l1;
import androidx.compose.runtime.C0775b0;
import androidx.compose.runtime.X;
import androidx.compose.runtime.Z;
import androidx.lifecycle.Y;
import coil3.i;
import coil3.n;
import coil3.request.m;
import com.comscore.streaming.EventType;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.common.internal.k;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3473j;
import com.google.android.material.shape.e;
import com.google.firebase.crashlytics.internal.persistence.c;
import com.quizlet.data.model.F;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields;
import com.quizlet.features.match.data.C4359o;
import com.quizlet.features.match.data.M;
import com.quizlet.features.match.data.W;
import com.quizlet.features.setpage.viewmodel.C4437k;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.infra.legacysyncengine.features.properties.d;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.joincontenttofolder.SelectableFolderListFragment;
import com.quizlet.qutils.string.f;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.io.File;
import java.io.IOException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;
import kotlin.collections.C;
import kotlin.collections.C4933y;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.v;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes2.dex */
public final class b implements InterfaceC0161b0, h, dagger.android.b {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ b(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public static final ArrayList a(b bVar, List list, boolean z) {
        if (z) {
            ArrayList arrayList = new ArrayList();
            for (Object obj : list) {
                if (((F) obj).e == null) {
                    arrayList.add(obj);
                }
            }
            list = arrayList;
        }
        ArrayList arrayList2 = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList2.add(Long.valueOf(((F) it2.next()).c));
        }
        return arrayList2;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        f fVar;
        f fVar2;
        switch (this.a) {
            case 21:
                Boolean canShareAll = (Boolean) obj;
                Intrinsics.checkNotNullParameter(canShareAll, "canShareAll");
                if (canShareAll.booleanValue()) {
                    return p.f(com.quizlet.features.infra.basestudy.data.models.shareset.a.a);
                }
                P p = (P) this.b;
                e eVar = p.u;
                d dVar = (d) this.c;
                Intrinsics.d(dVar);
                return eVar.v(p.d, dVar).g(C4437k.b);
            case EventType.SUBS /* 25 */:
                Intrinsics.checkNotNullParameter((File) obj, "<unused var>");
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.DIAGRAM_SHAPE);
                bVar.b(Long.valueOf(((com.quizlet.quizletandroid.data.management.a) this.b).a.getId()), DBDiagramShapeFields.SET_ID);
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
                Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
                return new io.reactivex.rxjava3.internal.operators.maybe.e(((s) this.c).o(aVarA), 3);
            default:
                v vVar = (v) obj;
                Intrinsics.checkNotNullParameter(vVar, "<destruct>");
                Object obj2 = vVar.a;
                Intrinsics.checkNotNullExpressionValue(obj2, "component1(...)");
                Object obj3 = vVar.b;
                Intrinsics.checkNotNullExpressionValue(obj3, "component2(...)");
                M m = (M) obj3;
                Object obj4 = vVar.c;
                Intrinsics.checkNotNullExpressionValue(obj4, "component3(...)");
                W w = (W) obj4;
                long jLongValue = ((Long) obj2).longValue();
                com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a aVar = (com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.a) this.b;
                com.quizlet.features.match.highscore.a aVar2 = (com.quizlet.features.match.highscore.a) this.c;
                DecimalFormat decimalFormat = aVar.o;
                long j = aVar2.b;
                String str = decimalFormat.format(j / 10.0d);
                Intrinsics.checkNotNullExpressionValue(str, "format(...)");
                Object[] args = {str};
                Intrinsics.checkNotNullParameter(args, "args");
                f fVar3 = new f(R.string.number_with_seconds, C4933y.P(args));
                if (aVar.f.k || jLongValue != j) {
                    Object[] args2 = new Object[0];
                    Intrinsics.checkNotNullParameter(args2, "args");
                    fVar = new f(R.string.you_finished_in, C4933y.P(args2));
                } else {
                    Object[] args3 = new Object[0];
                    Intrinsics.checkNotNullParameter(args3, "args");
                    fVar = new f(R.string.new_high_score, C4933y.P(args3));
                }
                if (jLongValue == j) {
                    Object[] args4 = new Object[0];
                    Intrinsics.checkNotNullParameter(args4, "args");
                    fVar2 = new f(R.string.match_leaderboard_new_personal_record, C4933y.P(args4));
                } else {
                    String str2 = decimalFormat.format(jLongValue / 10.0d);
                    Intrinsics.checkNotNullExpressionValue(str2, "format(...)");
                    Object[] args5 = {str2};
                    Intrinsics.checkNotNullParameter(args5, "args");
                    fVar2 = new f(R.string.match_leaderboard_your_personal_record, C4933y.P(args5));
                }
                return new C4359o(fVar3, fVar, fVar2, m, w);
        }
    }

    @Override // androidx.camera.core.impl.InterfaceC0161b0
    public void b(InterfaceC0159a0 interfaceC0159a0) {
        synchronized (((HashMap) this.c)) {
            try {
                U u = (U) ((HashMap) this.c).remove(interfaceC0159a0);
                if (u != null) {
                    u.a.set(false);
                    T.e().execute(new r(14, this, u));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // androidx.camera.core.impl.InterfaceC0161b0
    public void c(Executor executor, InterfaceC0159a0 interfaceC0159a0) {
        synchronized (((HashMap) this.c)) {
            U u = (U) ((HashMap) this.c).get(interfaceC0159a0);
            if (u != null) {
                u.a.set(false);
            }
            U u2 = new U(executor, (p0) interfaceC0159a0);
            ((HashMap) this.c).put(interfaceC0159a0, u2);
            T.e().execute(new RunnableC0130g(this, u, u2, 3));
        }
    }

    @Override // dagger.android.b
    public void d(Object obj) {
        SelectableFolderListFragment selectableFolderListFragment = (SelectableFolderListFragment) obj;
        C4622e c4622e = (C4622e) this.c;
        selectableFolderListFragment.a = c4622e.a();
        selectableFolderListFragment.b = ((u) this.b).S0();
        selectableFolderListFragment.s = c4622e.e();
    }

    public void e() throws IOException {
        String str = (String) this.b;
        try {
            c cVar = (c) this.c;
            cVar.getClass();
            new File(cVar.c, str).createNewFile();
        } catch (IOException e) {
            Log.e("FirebaseCrashlytics", "Error creating marker: ".concat(str), e);
        }
    }

    public void f(int[] iArr, int i) {
        com.google.zxing.common.reedsolomon.b bVar;
        com.google.zxing.common.reedsolomon.b bVar2;
        com.google.zxing.common.reedsolomon.b bVar3;
        if (i == 0) {
            throw new IllegalArgumentException("No error correction bytes");
        }
        int length = iArr.length - i;
        if (length <= 0) {
            throw new IllegalArgumentException("No data bytes provided");
        }
        ArrayList arrayList = (ArrayList) this.c;
        int size = arrayList.size();
        int i2 = 0;
        int i3 = 1;
        com.google.zxing.common.reedsolomon.a aVar = (com.google.zxing.common.reedsolomon.a) this.b;
        if (i >= size) {
            com.google.zxing.common.reedsolomon.b bVar4 = (com.google.zxing.common.reedsolomon.b) android.support.v4.media.session.a.e(1, arrayList);
            int size2 = arrayList.size();
            while (size2 <= i) {
                int[] iArr2 = {i3, aVar.a[(size2 - 1) + aVar.f]};
                if (iArr2[i2] == 0) {
                    int i4 = i3;
                    while (i4 < 2 && iArr2[i4] == 0) {
                        i4++;
                    }
                    if (i4 == 2) {
                        iArr2 = new int[]{i2};
                    } else {
                        int i5 = 2 - i4;
                        int[] iArr3 = new int[i5];
                        System.arraycopy(iArr2, i4, iArr3, i2, i5);
                        iArr2 = iArr3;
                    }
                }
                bVar4.getClass();
                com.google.zxing.common.reedsolomon.a aVar2 = bVar4.a;
                if (!aVar2.equals(aVar)) {
                    throw new IllegalArgumentException("GenericGFPolys do not have same GenericGF field");
                }
                int[] iArr4 = bVar4.b;
                if (iArr4[i2] == 0 || iArr2[i2] == 0) {
                    bVar4 = aVar2.c;
                } else {
                    int length2 = iArr4.length;
                    int length3 = iArr2.length;
                    int[] iArr5 = new int[(length2 + length3) - i3];
                    for (int i6 = i2; i6 < length2; i6++) {
                        int i7 = iArr4[i6];
                        int i8 = 0;
                        while (i8 < length3) {
                            int i9 = i6 + i8;
                            int i10 = i8;
                            iArr5[i9] = iArr5[i9] ^ aVar2.a(i7, iArr2[i10]);
                            i8 = i10 + 1;
                        }
                    }
                    bVar4 = new com.google.zxing.common.reedsolomon.b(aVar2, iArr5);
                }
                arrayList.add(bVar4);
                size2++;
                i2 = 0;
                i3 = 1;
            }
        }
        com.google.zxing.common.reedsolomon.b bVar5 = (com.google.zxing.common.reedsolomon.b) arrayList.get(i);
        int[] iArr6 = new int[length];
        System.arraycopy(iArr, 0, iArr6, 0, length);
        if (length == 0) {
            throw new IllegalArgumentException();
        }
        if (length > 1 && iArr6[0] == 0) {
            int i11 = 1;
            while (i11 < length && iArr6[i11] == 0) {
                i11++;
            }
            if (i11 == length) {
                iArr6 = new int[]{0};
            } else {
                int i12 = length - i11;
                int[] iArr7 = new int[i12];
                System.arraycopy(iArr6, i11, iArr7, 0, i12);
                iArr6 = iArr7;
            }
        }
        if (i < 0) {
            throw new IllegalArgumentException();
        }
        int length4 = iArr6.length;
        int[] iArr8 = new int[length4 + i];
        for (int i13 = 0; i13 < length4; i13++) {
            iArr8[i13] = aVar.a(iArr6[i13], 1);
        }
        com.google.zxing.common.reedsolomon.b bVar6 = new com.google.zxing.common.reedsolomon.b(aVar, iArr8);
        if (!aVar.equals(bVar5.a)) {
            throw new IllegalArgumentException("GenericGFPolys do not have same GenericGF field");
        }
        int[] iArr9 = bVar5.b;
        if (iArr9[0] == 0) {
            throw new IllegalArgumentException("Divide by 0");
        }
        if (iArr9[(iArr9.length - 1) - bVar5.b()] == 0) {
            throw new ArithmeticException();
        }
        int i14 = aVar.a[(aVar.d - aVar.b[r6]) - 1];
        com.google.zxing.common.reedsolomon.b bVar7 = aVar.c;
        com.google.zxing.common.reedsolomon.b bVarA = bVar7;
        while (bVar6.b() >= bVar5.b()) {
            int[] iArr10 = bVar6.b;
            if (iArr10[0] == 0) {
                break;
            }
            int iB = bVar6.b() - bVar5.b();
            int iA = aVar.a(iArr10[(iArr10.length - 1) - bVar6.b()], i14);
            if (iB < 0) {
                throw new IllegalArgumentException();
            }
            com.google.zxing.common.reedsolomon.a aVar3 = bVar5.a;
            if (iA == 0) {
                bVar2 = aVar3.c;
                bVar = bVar5;
            } else {
                int length5 = iArr9.length;
                int[] iArr11 = new int[length5 + iB];
                int i15 = 0;
                while (i15 < length5) {
                    iArr11[i15] = aVar3.a(iArr9[i15], iA);
                    i15++;
                    bVar5 = bVar5;
                }
                bVar = bVar5;
                bVar2 = new com.google.zxing.common.reedsolomon.b(aVar3, iArr11);
            }
            if (iB < 0) {
                throw new IllegalArgumentException();
            }
            if (iA == 0) {
                bVar3 = bVar7;
            } else {
                int[] iArr12 = new int[iB + 1];
                iArr12[0] = iA;
                bVar3 = new com.google.zxing.common.reedsolomon.b(aVar, iArr12);
            }
            bVarA = bVarA.a(bVar3);
            bVar6 = bVar6.a(bVar2);
            bVar5 = bVar;
        }
        int[] iArr13 = new com.google.zxing.common.reedsolomon.b[]{bVarA, bVar6}[1].b;
        int length6 = i - iArr13.length;
        for (int i16 = 0; i16 < length6; i16++) {
            iArr[length + i16] = 0;
        }
        System.arraycopy(iArr13, 0, iArr, length + length6, iArr13.length);
    }

    public g g(androidx.work.impl.model.c userProps, Object obj) {
        d contentProps = (d) obj;
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(contentProps, "contentProps");
        g gVarE = ((com.google.firebase.heartbeatinfo.e) this.b).b(userProps, contentProps).e(new com.quizlet.data.repository.classfolder.e(this, userProps, contentProps, 15));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    public Object h(com.bumptech.glide.load.engine.bitmap_recycle.g gVar) {
        HashMap map = (HashMap) this.c;
        com.bumptech.glide.load.engine.bitmap_recycle.c cVar = (com.bumptech.glide.load.engine.bitmap_recycle.c) map.get(gVar);
        if (cVar == null) {
            cVar = new com.bumptech.glide.load.engine.bitmap_recycle.c(gVar);
            map.put(gVar, cVar);
        } else {
            gVar.a();
        }
        com.bumptech.glide.load.engine.bitmap_recycle.c cVar2 = cVar.d;
        cVar2.c = cVar.c;
        cVar.c.d = cVar2;
        com.bumptech.glide.load.engine.bitmap_recycle.c cVar3 = (com.bumptech.glide.load.engine.bitmap_recycle.c) this.b;
        cVar.d = cVar3;
        com.bumptech.glide.load.engine.bitmap_recycle.c cVar4 = cVar3.c;
        cVar.c = cVar4;
        cVar4.d = cVar;
        cVar.d.c = cVar;
        ArrayList arrayList = cVar.b;
        int size = arrayList != null ? arrayList.size() : 0;
        if (size > 0) {
            return cVar.b.remove(size - 1);
        }
        return null;
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x006a, code lost:
    
        if (r6 == r1) goto L26;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Enum i(long r6, boolean r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r5 = this;
            boolean r0 = r9 instanceof com.quizlet.features.folders.viewmodel.usecases.b
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.features.folders.viewmodel.usecases.b r0 = (com.quizlet.features.folders.viewmodel.usecases.b) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.features.folders.viewmodel.usecases.b r0 = new com.quizlet.features.folders.viewmodel.usecases.b
            r0.<init>(r5, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3e
            if (r2 == r4) goto L36
            if (r2 != r3) goto L2e
            androidx.glance.appwidget.protobuf.Z.e(r9)
            kotlin.r r9 = (kotlin.r) r9
            java.lang.Object r6 = r9.a
            goto L6d
        L2e:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L36:
            long r6 = r0.k
            com.quizlet.data.repository.activitycenter.b r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L55
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            if (r8 == 0) goto L84
            r0.j = r5
            r0.k = r6
            r0.n = r4
            java.lang.Object r8 = r5.b
            com.quizlet.featuregate.features.folder.b r8 = (com.quizlet.featuregate.features.folder.b) r8
            java.lang.Object r9 = r8.a(r0)
            if (r9 != r1) goto L54
            goto L6c
        L54:
            r8 = r5
        L55:
            java.lang.Boolean r9 = (java.lang.Boolean) r9
            boolean r9 = r9.booleanValue()
            if (r9 == 0) goto L84
            java.lang.Object r8 = r8.c
            com.quizlet.data.interactor.folder.f r8 = (com.quizlet.data.interactor.folder.f) r8
            r9 = 0
            r0.j = r9
            r0.n = r3
            java.lang.Object r6 = r8.b(r6, r0)
            if (r6 != r1) goto L6d
        L6c:
            return r1
        L6d:
            java.lang.Throwable r7 = kotlin.r.a(r6)
            if (r7 != 0) goto L74
            goto L76
        L74:
            java.lang.Boolean r6 = java.lang.Boolean.FALSE
        L76:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 == 0) goto L81
            com.quizlet.features.folders.data.a r6 = com.quizlet.features.folders.data.EnumC4270a.a
            return r6
        L81:
            com.quizlet.features.folders.data.a r6 = com.quizlet.features.folders.data.EnumC4270a.b
            return r6
        L84:
            com.quizlet.features.folders.data.a r6 = com.quizlet.features.folders.data.EnumC4270a.c
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.activitycenter.b.i(long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(com.quizlet.generated.enums.I0 r5, kotlin.coroutines.h r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.data.interactor.user.eligibility.b
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.data.interactor.user.eligibility.b r0 = (com.quizlet.data.interactor.user.eligibility.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.user.eligibility.b r0 = new com.quizlet.data.interactor.user.eligibility.b
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.generated.enums.I0 r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L58
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.util.Set r6 = kotlin.collections.Z.b(r5)
            r0.j = r5
            r0.m = r3
            com.quizlet.data.interactor.user.eligibility.a r2 = new com.quizlet.data.interactor.user.eligibility.a
            r3 = 0
            r2.<init>(r4, r6, r3)
            java.lang.Object r6 = r4.c
            com.quizlet.db.data.caches.UserInfoCache r6 = (com.quizlet.db.data.caches.UserInfoCache) r6
            boolean r6 = r6.b()
            if (r6 == 0) goto L51
            java.lang.Object r6 = r2.invoke(r0)
            goto L55
        L51:
            kotlin.collections.L r6 = kotlin.collections.V.c()
        L55:
            if (r6 != r1) goto L58
            return r1
        L58:
            java.util.Map r6 = (java.util.Map) r6
            java.lang.Object r5 = r6.get(r5)
            java.lang.Boolean r5 = (java.lang.Boolean) r5
            if (r5 == 0) goto L67
            boolean r5 = r5.booleanValue()
            goto L68
        L67:
            r5 = 0
        L68:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.activitycenter.b.j(com.quizlet.generated.enums.I0, kotlin.coroutines.h):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object k(java.lang.String r13, kotlin.coroutines.jvm.internal.c r14) throws java.lang.Throwable {
        /*
            r12 = this;
            boolean r0 = r14 instanceof com.quizlet.data.interactor.practicetests.a
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.data.interactor.practicetests.a r0 = (com.quizlet.data.interactor.practicetests.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.data.interactor.practicetests.a r0 = new com.quizlet.data.interactor.practicetests.a
            r0.<init>(r12, r14)
        L18:
            java.lang.Object r14 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            java.util.ArrayList r13 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L62
        L29:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r14 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r14)
            throw r13
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            java.lang.Object r14 = r12.c
            com.quizlet.db.data.caches.UserInfoCache r14 = (com.quizlet.db.data.caches.UserInfoCache) r14
            boolean r14 = r14.b()
            if (r14 != 0) goto L41
            kotlin.collections.K r13 = kotlin.collections.K.a
            return r13
        L41:
            java.util.ArrayList r14 = new java.util.ArrayList
            r14.<init>()
            r0.j = r14
            r0.m = r3
            java.lang.Object r2 = r12.b
            com.google.android.gms.internal.ads.C3 r2 = (com.google.android.gms.internal.ads.C3) r2
            com.quizlet.remote.model.practicetests.f r3 = new com.quizlet.remote.model.practicetests.f
            r4 = 0
            r3.<init>(r2, r13, r4)
            java.lang.Object r13 = r2.b
            kotlinx.coroutines.y r13 = (kotlinx.coroutines.AbstractC5040y) r13
            java.lang.Object r13 = kotlinx.coroutines.E.J(r13, r3, r0)
            if (r13 != r1) goto L5f
            return r1
        L5f:
            r11 = r14
            r14 = r13
            r13 = r11
        L62:
            java.util.List r14 = (java.util.List) r14
            java.util.Iterator r14 = r14.iterator()
        L68:
            boolean r0 = r14.hasNext()
            if (r0 == 0) goto Lb1
            java.lang.Object r0 = r14.next()
            com.quizlet.data.model.W0 r0 = (com.quizlet.data.model.W0) r0
            com.quizlet.data.model.V0 r1 = new com.quizlet.data.model.V0
            java.lang.String r2 = r0.a
            java.lang.String r3 = r0.b
            java.lang.String r4 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r4)
            java.time.Instant r3 = java.time.Instant.parse(r3)
            java.time.ZoneOffset r4 = java.time.ZoneOffset.UTC
            java.time.OffsetDateTime r3 = r3.atOffset(r4)
            java.time.LocalDate r3 = r3.toLocalDate()
            java.time.format.FormatStyle r4 = java.time.format.FormatStyle.MEDIUM
            java.time.format.DateTimeFormatter r4 = java.time.format.DateTimeFormatter.ofLocalizedDate(r4)
            java.lang.String r3 = r3.format(r4)
            java.lang.String r4 = "format(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r4)
            int r7 = r0.d
            double r4 = (double) r7
            int r8 = r0.e
            double r9 = (double) r8
            double r4 = r4 / r9
            r6 = 100
            double r9 = (double) r6
            double r4 = r4 * r9
            int r6 = (int) r4
            long r4 = r0.c
            r1.<init>(r2, r3, r4, r6, r7, r8)
            r13.add(r1)
            goto L68
        Lb1:
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.activitycenter.b.k(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0039  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public coil3.request.m l(coil3.request.g r13, coil3.size.h r14) {
        /*
            r12 = this;
            coil3.request.m r0 = new coil3.request.m
            android.content.Context r1 = r13.a
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e r2 = coil3.request.i.b
            java.lang.Object r3 = coil3.n.d(r13, r2)
            android.graphics.Bitmap$Config r3 = (android.graphics.Bitmap.Config) r3
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e r4 = coil3.request.i.g
            java.lang.Object r5 = coil3.n.d(r13, r4)
            java.lang.Boolean r5 = (java.lang.Boolean) r5
            boolean r5 = r5.booleanValue()
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e r6 = coil3.request.h.a
            java.lang.Object r7 = coil3.n.d(r13, r6)
            java.util.List r7 = (java.util.List) r7
            boolean r7 = r7.isEmpty()
            r8 = 0
            r9 = 1
            if (r7 != 0) goto L39
            android.graphics.Bitmap$Config[] r7 = coil3.util.l.a
            java.lang.Object r10 = coil3.n.d(r13, r2)
            android.graphics.Bitmap$Config r10 = (android.graphics.Bitmap.Config) r10
            boolean r7 = kotlin.collections.C4933y.u(r10, r7)
            if (r7 == 0) goto L37
            goto L39
        L37:
            r7 = r8
            goto L3a
        L39:
            r7 = r9
        L3a:
            java.lang.Object r10 = coil3.n.d(r13, r2)
            android.graphics.Bitmap$Config r10 = (android.graphics.Bitmap.Config) r10
            android.graphics.Bitmap$Config r11 = android.graphics.Bitmap.Config.HARDWARE
            if (r10 != r11) goto L68
            java.lang.Object r10 = coil3.n.d(r13, r2)
            android.graphics.Bitmap$Config r10 = (android.graphics.Bitmap.Config) r10
            if (r10 != r11) goto L5b
            androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e r10 = coil3.request.i.f
            java.lang.Object r10 = coil3.n.d(r13, r10)
            java.lang.Boolean r10 = (java.lang.Boolean) r10
            boolean r10 = r10.booleanValue()
            if (r10 != 0) goto L5b
            goto L66
        L5b:
            java.lang.Object r10 = r12.c
            coil3.util.d r10 = (coil3.util.d) r10
            boolean r10 = r10.a(r14)
            if (r10 == 0) goto L66
            goto L68
        L66:
            r10 = r8
            goto L69
        L68:
            r10 = r9
        L69:
            if (r7 == 0) goto L6e
            if (r10 == 0) goto L6e
            goto L70
        L6e:
            android.graphics.Bitmap$Config r3 = android.graphics.Bitmap.Config.ARGB_8888
        L70:
            if (r5 == 0) goto L83
            java.lang.Object r5 = coil3.n.d(r13, r6)
            java.util.List r5 = (java.util.List) r5
            boolean r5 = r5.isEmpty()
            if (r5 == 0) goto L83
            android.graphics.Bitmap$Config r5 = android.graphics.Bitmap.Config.ALPHA_8
            if (r3 == r5) goto L83
            r8 = r9
        L83:
            coil3.request.e r5 = r13.t
            coil3.i r5 = r5.n
            java.util.Map r5 = r5.a
            coil3.i r6 = r13.r
            java.util.Map r6 = r6.a
            java.util.LinkedHashMap r5 = kotlin.collections.V.h(r5, r6)
            java.util.LinkedHashMap r5 = kotlin.collections.V.m(r5)
            java.lang.Object r6 = coil3.n.d(r13, r2)
            android.graphics.Bitmap$Config r6 = (android.graphics.Bitmap.Config) r6
            if (r3 == r6) goto La6
            if (r3 == 0) goto La3
            r5.put(r2, r3)
            goto La6
        La3:
            r5.remove(r2)
        La6:
            java.lang.Object r2 = coil3.n.d(r13, r4)
            java.lang.Boolean r2 = (java.lang.Boolean) r2
            boolean r2 = r2.booleanValue()
            if (r8 == r2) goto Lb9
            java.lang.Boolean r2 = java.lang.Boolean.valueOf(r8)
            r5.put(r4, r2)
        Lb9:
            coil3.i r10 = new coil3.i
            java.util.Map r2 = com.google.android.gms.internal.mlkit_vision_common.AbstractC3473j.c(r5)
            r10.<init>(r2)
            coil3.request.b r8 = r13.j
            coil3.request.b r9 = r13.k
            coil3.size.g r3 = r13.p
            coil3.size.d r4 = r13.q
            r5 = 0
            okio.n r6 = r13.e
            coil3.request.b r7 = r13.i
            r2 = r14
            r0.<init>(r1, r2, r3, r4, r5, r6, r7, r8, r9, r10)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.activitycenter.b.l(coil3.request.g, coil3.size.h):coil3.request.m");
    }

    public void m(com.bumptech.glide.load.engine.bitmap_recycle.g gVar, Object obj) {
        HashMap map = (HashMap) this.c;
        com.bumptech.glide.load.engine.bitmap_recycle.c cVar = (com.bumptech.glide.load.engine.bitmap_recycle.c) map.get(gVar);
        if (cVar == null) {
            cVar = new com.bumptech.glide.load.engine.bitmap_recycle.c(gVar);
            cVar.d = cVar;
            com.bumptech.glide.load.engine.bitmap_recycle.c cVar2 = (com.bumptech.glide.load.engine.bitmap_recycle.c) this.b;
            cVar.d = cVar2.d;
            cVar.c = cVar2;
            cVar2.d = cVar;
            cVar.d.c = cVar;
            map.put(gVar, cVar);
        } else {
            gVar.a();
        }
        if (cVar.b == null) {
            cVar.b = new ArrayList();
        }
        cVar.b.add(obj);
    }

    public Object n() {
        com.bumptech.glide.load.engine.bitmap_recycle.c cVar = (com.bumptech.glide.load.engine.bitmap_recycle.c) this.b;
        com.bumptech.glide.load.engine.bitmap_recycle.c cVar2 = cVar.d;
        while (true) {
            if (cVar2.equals(cVar)) {
                return null;
            }
            ArrayList arrayList = cVar2.b;
            int size = arrayList != null ? arrayList.size() : 0;
            Object objRemove = size > 0 ? cVar2.b.remove(size - 1) : null;
            if (objRemove != null) {
                return objRemove;
            }
            com.bumptech.glide.load.engine.bitmap_recycle.c cVar3 = cVar2.d;
            cVar3.c = cVar2.c;
            cVar2.c.d = cVar3;
            HashMap map = (HashMap) this.c;
            com.bumptech.glide.load.engine.bitmap_recycle.g gVar = cVar2.a;
            map.remove(gVar);
            gVar.a();
            cVar2 = cVar2.d;
        }
    }

    public m o(m mVar) {
        i iVar;
        boolean z;
        i iVar2 = mVar.j;
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e eVar = coil3.request.i.b;
        if (((Bitmap.Config) n.e(mVar, eVar)) != Bitmap.Config.HARDWARE || ((coil3.util.d) this.c).c()) {
            iVar = iVar2;
            z = false;
        } else {
            iVar2.getClass();
            LinkedHashMap linkedHashMapM = V.m(iVar2.a);
            Bitmap.Config config = Bitmap.Config.ARGB_8888;
            if (config != null) {
                linkedHashMapM.put(eVar, config);
            } else {
                linkedHashMapM.remove(eVar);
            }
            i iVar3 = new i(AbstractC3473j.c(linkedHashMapM));
            z = true;
            iVar = iVar3;
        }
        if (!z) {
            return mVar;
        }
        return new m(mVar.a, mVar.b, mVar.c, mVar.d, mVar.e, mVar.f, mVar.g, mVar.h, mVar.i, iVar);
    }

    public void p(Z z) {
        Object objF = ((I) this.c).f(z);
        if (objF != null) {
            boolean z2 = objF instanceof G;
            I i = (I) this.b;
            if (!z2) {
                androidx.compose.runtime.collection.a.c(i, (X) objF, new C0775b0(z, 0));
                return;
            }
            G g = (G) objF;
            Object[] objArr = g.a;
            int i2 = g.b;
            for (int i3 = 0; i3 < i2; i3++) {
                Object obj = objArr[i3];
                Intrinsics.e(obj, "null cannot be cast to non-null type V of androidx.compose.runtime.collection.MultiValueMap");
                androidx.compose.runtime.collection.a.c(i, (X) obj, new C0775b0(z, 0));
            }
        }
    }

    public String toString() {
        switch (this.a) {
            case 7:
                StringBuilder sb = new StringBuilder("GroupedLinkedMap( ");
                com.bumptech.glide.load.engine.bitmap_recycle.c cVar = (com.bumptech.glide.load.engine.bitmap_recycle.c) this.b;
                com.bumptech.glide.load.engine.bitmap_recycle.c cVar2 = cVar.c;
                boolean z = false;
                while (!cVar2.equals(cVar)) {
                    sb.append('{');
                    sb.append(cVar2.a);
                    sb.append(':');
                    ArrayList arrayList = cVar2.b;
                    sb.append(arrayList != null ? arrayList.size() : 0);
                    sb.append("}, ");
                    cVar2 = cVar2.c;
                    z = true;
                }
                if (z) {
                    sb.delete(sb.length() - 2, sb.length());
                }
                sb.append(" )");
                return sb.toString();
            default:
                return super.toString();
        }
    }

    public b(Context context) {
        this.a = 10;
        this.c = new AtomicLong(-1L);
        this.b = com.google.android.gms.common.internal.u.n(context, new k("mlkit:vision"));
    }

    public b(String str, com.google.android.gms.auth.api.b bVar, com.google.mlkit.common.sdkinternal.b bVar2) {
        this.a = 9;
        this.c = str;
        this.b = bVar;
    }

    public b(com.quizlet.data.repository.user.a userLocalDataStore, com.quizlet.remote.model.user.a userRemoteDataStore) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(userLocalDataStore, "userLocalDataStore");
        Intrinsics.checkNotNullParameter(userRemoteDataStore, "userRemoteDataStore");
        this.b = userLocalDataStore;
        this.c = userRemoteDataStore;
    }

    public b(s database, com.quizlet.shared.usecase.folderstudymaterials.a mapper) {
        this.a = 22;
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = mapper;
        this.c = (com.google.mlkit.vision.documentscanner.internal.c) database.e;
    }

    public b(com.quizlet.featuregate.features.folder.b addFolderToLibraryEligibility, com.quizlet.data.interactor.folder.f copyFolderUseCase) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(addFolderToLibraryEligibility, "addFolderToLibraryEligibility");
        Intrinsics.checkNotNullParameter(copyFolderUseCase, "copyFolderUseCase");
        this.b = addFolderToLibraryEligibility;
        this.c = copyFolderUseCase;
    }

    public b(com.quizlet.login.common.interactors.d adsTrackingRemote, o ioScheduler) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(adsTrackingRemote, "adsTrackingRemote");
        Intrinsics.checkNotNullParameter(ioScheduler, "ioScheduler");
        this.b = adsTrackingRemote;
        this.c = ioScheduler;
    }

    public b(C3 practiceTestsRepository, UserInfoCache userInfoCache) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(practiceTestsRepository, "practiceTestsRepository");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        this.b = practiceTestsRepository;
        this.c = userInfoCache;
    }

    public b(com.quizlet.quizletandroid.braze.data.a activityCenterRemoteDataStore, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(activityCenterRemoteDataStore, "activityCenterRemoteDataStore");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = activityCenterRemoteDataStore;
        this.c = networkStatus;
    }

    public b(AbstractC5040y dispatcher, com.quizlet.data.connectivity.a networkStatus) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        this.b = dispatcher;
        this.c = networkStatus;
    }

    public b(com.quizlet.local.ormlite.models.bookmark.a classSetLocal, com.quizlet.local.ormlite.models.studysetwithcreator.a studySetWithCreatorLocal) {
        this.a = 23;
        Intrinsics.checkNotNullParameter(classSetLocal, "classSetLocal");
        Intrinsics.checkNotNullParameter(studySetWithCreatorLocal, "studySetWithCreatorLocal");
        this.b = classSetLocal;
        this.c = studySetWithCreatorLocal;
    }

    public b(com.quizlet.login.common.interactors.d repository, androidx.work.impl.model.c dispatcher) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = repository;
        this.c = dispatcher;
    }

    public b(com.quizlet.data.repository.user.eligibility.g userFeatureEligibilityRepository, UserInfoCache userInfoCache) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(userFeatureEligibilityRepository, "userFeatureEligibilityRepository");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        this.b = userFeatureEligibilityRepository;
        this.c = userInfoCache;
    }

    public b(l1 repository, AbstractC5040y ioDispatcher) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = repository;
        this.c = ioDispatcher;
    }

    public b(com.google.firebase.heartbeatinfo.e shareSetFeature, e shareSetByEmailFeature) {
        this.a = 26;
        Intrinsics.checkNotNullParameter(shareSetFeature, "shareSetFeature");
        Intrinsics.checkNotNullParameter(shareSetByEmailFeature, "shareSetByEmailFeature");
        this.b = shareSetFeature;
        this.c = shareSetByEmailFeature;
    }

    public b(io.ktor.client.plugins.api.d studySetsWithCreatorUseCase, androidx.work.impl.model.e termUseCase) {
        this.a = 27;
        Intrinsics.checkNotNullParameter(studySetsWithCreatorUseCase, "studySetsWithCreatorUseCase");
        Intrinsics.checkNotNullParameter(termUseCase, "termUseCase");
        this.b = studySetsWithCreatorUseCase;
        this.c = termUseCase;
    }

    public b(com.google.zxing.common.reedsolomon.a aVar) {
        this.a = 13;
        this.b = aVar;
        ArrayList arrayList = new ArrayList();
        this.c = arrayList;
        arrayList.add(new com.google.zxing.common.reedsolomon.b(aVar, new int[]{1}));
    }

    public b(coil3.u uVar) {
        Object hVar;
        this.a = 6;
        this.b = uVar;
        int i = Build.VERSION.SDK_INT;
        if (coil3.util.e.a) {
            hVar = new androidx.camera.camera2.internal.compat.workaround.e(false, 4);
        } else if (i != 26 && i != 27) {
            hVar = new androidx.camera.camera2.internal.compat.workaround.e(true, 4);
        } else {
            hVar = new coil3.util.h();
        }
        this.c = hVar;
    }

    public b(int i) {
        this.a = i;
        switch (i) {
            case 3:
                this.b = new I();
                this.c = new I();
                break;
            case 4:
                this.b = new com.google.android.gms.internal.mlkit_common.u(3);
                this.c = new androidx.compose.ui.text.caches.b(16);
                break;
            case 7:
                this.b = new com.bumptech.glide.load.engine.bitmap_recycle.c(null);
                this.c = new HashMap();
                break;
            case 11:
                this.b = new Rect();
                this.c = new Rect();
                break;
            default:
                this.b = new Y();
                this.c = new HashMap();
                break;
        }
    }

    public b(Context context, Object obj, LinkedHashSet linkedHashSet) {
        q qVarA;
        this.a = 1;
        com.google.firebase.perf.logging.b bVar = new com.google.firebase.perf.logging.b(1);
        this.b = new HashMap();
        this.c = bVar;
        if (obj instanceof q) {
            qVarA = (q) obj;
        } else {
            qVarA = q.a(context, androidx.camera.core.impl.utils.e.b());
        }
        Iterator it2 = linkedHashSet.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            ((HashMap) this.b).put(str, new f0(context, str, qVarA, (com.google.firebase.perf.logging.b) this.c));
        }
    }

    public b(Bundle savedState, LinkedHashMap typeMap) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(savedState, "savedState");
        Intrinsics.checkNotNullParameter(typeMap, "typeMap");
        this.b = savedState;
        this.c = typeMap;
    }
}
