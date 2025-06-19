package com.quizlet.data.repository.folderwithcreator;

import android.os.Build;
import android.text.Editable;
import android.text.Selection;
import android.text.TextPaint;
import android.util.SparseArray;
import android.view.KeyEvent;
import android.view.View;
import android.widget.LinearLayout;
import androidx.camera.core.h0;
import androidx.collection.C0219q;
import androidx.compose.ui.layout.r;
import androidx.core.graphics.f;
import androidx.emoji2.text.v;
import androidx.emoji2.text.y;
import androidx.emoji2.text.z;
import androidx.legacy.widget.Space;
import androidx.webkit.internal.p;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.internal.measurement.C3083y1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_barcode.U;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3348i;
import com.google.android.gms.internal.mlkit_vision_common.K2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C3676n;
import com.iabtcf.utils.l;
import com.j256.ormlite.dao.Dao;
import com.quizlet.data.model.C4127f1;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.explanations.databinding.n;
import com.quizlet.generated.enums.G1;
import com.quizlet.generated.enums.P;
import com.quizlet.local.datastore.preferences.C4566c0;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.C4633r;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeResultsView;
import com.quizlet.remote.service.InterfaceC4775b;
import com.quizlet.remote.service.m;
import io.reactivex.rxjava3.core.g;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.io.File;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.function.Function;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.text.StringsKt;
import kotlin.text.x;
import kotlin.u;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class e implements androidx.camera.core.impl.utils.futures.c, com.google.firebase.encoders.config.a, h, com.quizlet.data.repository.metering.a {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;

    public /* synthetic */ e(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    public static boolean c(Editable editable, KeyEvent keyEvent, boolean z) {
        z[] zVarArr;
        if (KeyEvent.metaStateHasNoModifiers(keyEvent.getMetaState())) {
            int selectionStart = Selection.getSelectionStart(editable);
            int selectionEnd = Selection.getSelectionEnd(editable);
            if (selectionStart != -1 && selectionEnd != -1 && selectionStart == selectionEnd && (zVarArr = (z[]) editable.getSpans(selectionStart, selectionEnd, z.class)) != null && zVarArr.length > 0) {
                for (z zVar : zVarArr) {
                    int spanStart = editable.getSpanStart(zVar);
                    int spanEnd = editable.getSpanEnd(zVar);
                    if ((z && spanStart == selectionStart) || ((!z && spanEnd == selectionStart) || (selectionStart > spanStart && selectionStart < spanEnd))) {
                        editable.delete(spanStart, spanEnd);
                        return true;
                    }
                }
            }
        }
        return false;
    }

    @Override // com.quizlet.data.repository.metering.a
    public Object a(long j, Long l, P p, kotlin.coroutines.jvm.internal.c cVar) {
        return E.J((AbstractC5040y) this.d, new com.quizlet.remote.model.metering.a(this, p, l, j, null), cVar);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 14:
                File it2 = (File) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return ((com.quizlet.quizletandroid.ui.common.images.loading.offline.c) ((s) this.b).c).a(((com.quizlet.qutils.data.offline.d) this.c).a((String) this.d, com.quizlet.qutils.data.offline.b.c));
            default:
                File cacheFile = (File) obj;
                Intrinsics.checkNotNullParameter(cacheFile, "cacheFile");
                return cacheFile.exists() ? g.c(cacheFile) : com.quizlet.quizletandroid.ui.common.images.loading.offline.c.c((com.quizlet.quizletandroid.ui.common.images.loading.offline.c) this.b, (String) this.c, cacheFile, (com.quizlet.quizletandroid.data.cache.a) this.d);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00a2  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00b3  */
    /* JADX WARN: Type inference failed for: r15v8, types: [java.lang.Object[]] */
    /* JADX WARN: Type inference failed for: r19v3 */
    /* JADX WARN: Type inference failed for: r19v4 */
    /* JADX WARN: Type inference failed for: r19v5 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void b(long r22, java.util.List r24, boolean r25) {
        /*
            Method dump skipped, instructions count: 330
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folderwithcreator.e.b(long, java.util.List, boolean):void");
    }

    public boolean d(C3083y1 c3083y1, boolean z) {
        boolean z2;
        boolean z3;
        p pVar = (p) this.c;
        if (pVar.i((C0219q) c3083y1.c, (r) this.b, c3083y1, z)) {
            androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) pVar.b;
            int i = bVar.c;
            if (i > 0) {
                Object[] objArr = bVar.a;
                int i2 = 0;
                z2 = false;
                do {
                    z2 = ((androidx.compose.ui.input.pointer.e) objArr[i2]).C(c3083y1, z) || z2;
                    i2++;
                } while (i2 < i);
            } else {
                z2 = false;
            }
            int i3 = bVar.c;
            if (i3 > 0) {
                Object[] objArr2 = bVar.a;
                int i4 = 0;
                z3 = false;
                do {
                    z3 = ((androidx.compose.ui.input.pointer.e) objArr2[i4]).B(c3083y1) || z3;
                    i4++;
                } while (i4 < i3);
            } else {
                z3 = false;
            }
            pVar.l(c3083y1);
            if (z3 || z2) {
                return true;
            }
        }
        return false;
    }

    public io.reactivex.rxjava3.internal.operators.observable.r e(io.reactivex.rxjava3.internal.operators.single.g gVar, io.reactivex.rxjava3.core.p pVar) {
        J j = new J(pVar.m(), new com.google.android.material.floatingactionbutton.c(this, 14), 4);
        Intrinsics.checkNotNullExpressionValue(j, "onErrorResumeNext(...)");
        J j2 = new J(new com.jakewharton.rxbinding4.a(new a(this, gVar, pVar, 0), 4), new com.quizlet.data.interactor.course.a(this, 7), 4);
        Intrinsics.checkNotNullExpressionValue(j2, "onErrorResumeNext(...)");
        io.reactivex.rxjava3.internal.operators.observable.r rVarG = i.g(j, j2);
        Intrinsics.checkNotNullExpressionValue(rVarG, "concat(...)");
        return rVarG;
    }

    public J f(long j) {
        androidx.work.impl.model.e eVar = (androidx.work.impl.model.e) this.b;
        com.quizlet.remote.model.union.folderwithcreator.e eVar2 = (com.quizlet.remote.model.union.folderwithcreator.e) eVar.c;
        List personIds = A.b(Long.valueOf(j));
        Intrinsics.checkNotNullParameter(personIds, "userIds");
        com.quizlet.remote.model.union.folderwithcreator.b bVar = eVar2.a;
        Intrinsics.checkNotNullParameter(personIds, "personIds");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = ((InterfaceC4775b) bVar.b).a(null, U.c(personIds)).g(com.quizlet.remote.model.union.folderwithcreator.a.a).e(new com.quizlet.login.authentication.login.a(bVar, 18));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        io.reactivex.rxjava3.internal.operators.single.g gVarB = com.quizlet.remote.model.union.folderwithcreator.e.b(eVar2, gVarE);
        com.quizlet.local.ormlite.models.bookmark.a aVar = (com.quizlet.local.ormlite.models.bookmark.a) eVar.b;
        com.quizlet.local.ormlite.models.bookmark.a aVar2 = (com.quizlet.local.ormlite.models.bookmark.a) aVar.d;
        Object value = ((com.quizlet.local.ormlite.database.dao.b) aVar2.d).b.getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        io.reactivex.rxjava3.internal.operators.single.g gVarE2 = AbstractC3771z.b((com.google.mlkit.common.sdkinternal.b) aVar2.c, com.quizlet.local.ormlite.util.b.b((Dao) value, x.d("\n            SELECT * FROM bookmark\n            WHERE personId = " + j + "\n            AND isDeleted = 0\n        "))).g(new com.lyft.android.scissors.b(new C4566c0(13), 24)).e(new com.google.mlkit.vision.documentscanner.internal.c(aVar, 27));
        Intrinsics.checkNotNullExpressionValue(gVarE2, "flatMap(...)");
        J jQ = e(gVarB, gVarE2).q(d.a);
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        return jQ;
    }

    @Override // com.google.firebase.encoders.config.a
    public /* bridge */ /* synthetic */ com.google.firebase.encoders.config.a g(Class cls, com.google.firebase.encoders.c cVar) {
        ((HashMap) this.b).put(cls, cVar);
        ((HashMap) this.c).remove(cls);
        return this;
    }

    public J h(List creatorIds) {
        Intrinsics.checkNotNullParameter(creatorIds, "userIds");
        androidx.work.impl.model.e eVar = (androidx.work.impl.model.e) this.b;
        com.quizlet.remote.model.union.folderwithcreator.e eVar2 = (com.quizlet.remote.model.union.folderwithcreator.e) eVar.c;
        Intrinsics.checkNotNullParameter(creatorIds, "userIds");
        com.quizlet.remote.model.union.folderwithcreator.b bVar = eVar2.a;
        Intrinsics.checkNotNullParameter(creatorIds, "personIds");
        io.reactivex.rxjava3.internal.operators.single.g gVarB = com.quizlet.remote.model.union.folderwithcreator.e.b(eVar2, ((m) bVar.a).j(U.c(creatorIds), false));
        com.quizlet.local.ormlite.models.bookmark.a aVar = (com.quizlet.local.ormlite.models.bookmark.a) eVar.b;
        Intrinsics.checkNotNullParameter(creatorIds, "userIds");
        com.quizlet.local.ormlite.models.bookmark.a aVar2 = (com.quizlet.local.ormlite.models.bookmark.a) aVar.b;
        Intrinsics.checkNotNullParameter(creatorIds, "creatorIds");
        com.google.android.material.floatingactionbutton.c cVar = (com.google.android.material.floatingactionbutton.c) aVar2.d;
        Intrinsics.checkNotNullParameter(creatorIds, "userIds");
        Dao daoH = cVar.h();
        Intrinsics.checkNotNullParameter(creatorIds, "creatorIds");
        J jQ = e(gVarB, aVar.d(AbstractC3771z.b((com.quizlet.local.ormlite.models.folder.a) aVar2.c, com.quizlet.local.ormlite.util.b.b(daoH, x.c("\n                SELECT * FROM folder\n                WHERE personId IN " + com.google.android.gms.internal.mlkit_vision_document_scanner.A.b(creatorIds) + "\n                AND isDeleted = 0\n        "))))).q(d.a);
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        return jQ;
    }

    public i i(long j, long j2) {
        com.quizlet.data.repository.progress.c cVar = new com.quizlet.data.repository.progress.c(j, j2, G1.SET);
        com.google.firebase.crashlytics.internal.settings.b bVar = (com.google.firebase.crashlytics.internal.settings.b) this.b;
        List progressResetIds = A.b(cVar);
        Intrinsics.checkNotNullParameter(progressResetIds, "ids");
        Object value = ((u) bVar.b).getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        Dao dao = (Dao) value;
        Intrinsics.checkNotNullParameter(progressResetIds, "progressResetIds");
        String strS = progressResetIds.isEmpty() ? "0" : CollectionsKt.S(progressResetIds, " OR ", "(", ")", new com.quizlet.local.ormlite.database.dao.c(), 24);
        io.reactivex.rxjava3.internal.operators.single.g gVarG = com.quizlet.local.ormlite.util.b.b(dao, x.c("\nSELECT * FROM progress_reset\nWHERE " + strS + "\nAND " + com.google.android.gms.internal.mlkit_vision_document_scanner.A.a(true) + "\n    ")).g(com.quizlet.local.ormlite.database.a.a);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        i iVarM = gVarG.g(new com.google.firebase.messaging.p(this, 26)).m();
        Intrinsics.checkNotNullExpressionValue(iVarM, "toObservable(...)");
        return iVarM;
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x0079  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(kotlin.coroutines.jvm.internal.c r7) {
        /*
            r6 = this;
            boolean r0 = r7 instanceof com.quizlet.featuregate.features.learn.a
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.featuregate.features.learn.a r0 = (com.quizlet.featuregate.features.learn.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.featuregate.features.learn.a r0 = new com.quizlet.featuregate.features.learn.a
            r0.<init>(r6, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 3
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L41
            if (r2 == r5) goto L3b
            if (r2 == r4) goto L35
            if (r2 != r3) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r7)
            return r7
        L2d:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r0)
            throw r7
        L35:
            com.quizlet.data.repository.folderwithcreator.e r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L71
        L3b:
            com.quizlet.data.repository.folderwithcreator.e r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L58
        L41:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r6.b
            androidx.work.impl.model.c r7 = (androidx.work.impl.model.c) r7
            io.reactivex.rxjava3.internal.operators.single.g r7 = r7.r()
            r0.j = r6
            r0.m = r5
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r7, r0)
            if (r7 != r1) goto L57
            goto L94
        L57:
            r2 = r6
        L58:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 != 0) goto L96
            java.lang.Object r7 = r2.c
            com.quizlet.data.repository.activitycenter.b r7 = (com.quizlet.data.repository.activitycenter.b) r7
            com.quizlet.generated.enums.I0 r5 = com.quizlet.generated.enums.I0.LEARN_MOBILE_NATIVE_IMPROVEMENTS
            r0.j = r2
            r0.m = r4
            java.lang.Object r7 = r7.j(r5, r0)
            if (r7 != r1) goto L71
            goto L94
        L71:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 == 0) goto L96
            java.lang.Object r7 = r2.d
            com.quizlet.quizletandroid.r r7 = (com.quizlet.quizletandroid.C4633r) r7
            com.quizlet.featuregate.contracts.enums.b r2 = com.quizlet.featuregate.contracts.enums.b.a
            java.lang.String r4 = "learn_simpler_onboarding"
            com.quizlet.remote.model.notes.e r7 = r7.a(r4, r2)
            r2 = 0
            r0.j = r2
            r0.m = r3
            java.lang.Object r0 = r7.e
            java.lang.Enum r0 = (java.lang.Enum) r0
            java.lang.Enum r7 = r7.k(r0)
            if (r7 != r1) goto L95
        L94:
            return r1
        L95:
            return r7
        L96:
            com.quizlet.featuregate.contracts.enums.b r7 = com.quizlet.featuregate.contracts.enums.b.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folderwithcreator.e.j(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public boolean k(CharSequence charSequence, int i, int i2, y yVar) {
        if ((yVar.c & 3) == 0) {
            androidx.emoji2.text.d dVar = (androidx.emoji2.text.d) this.d;
            androidx.emoji2.text.flatbuffer.a aVarB = yVar.b();
            int iA = aVarB.a(8);
            if (iA != 0) {
                ((ByteBuffer) aVarB.d).getShort(iA + aVarB.a);
            }
            dVar.getClass();
            ThreadLocal threadLocal = androidx.emoji2.text.d.b;
            if (threadLocal.get() == null) {
                threadLocal.set(new StringBuilder());
            }
            StringBuilder sb = (StringBuilder) threadLocal.get();
            sb.setLength(0);
            while (i < i2) {
                sb.append(charSequence.charAt(i));
                i++;
            }
            TextPaint textPaint = dVar.a;
            String string = sb.toString();
            int i3 = f.a;
            boolean zHasGlyph = textPaint.hasGlyph(string);
            int i4 = yVar.c & 4;
            yVar.c = zHasGlyph ? i4 | 2 : i4 | 1;
        }
        return (yVar.c & 3) == 2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:144:0x027e  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x0283  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x028d  */
    /* JADX WARN: Removed duplicated region for block: B:149:0x0292  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x0313  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x0316  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x0344  */
    /* JADX WARN: Removed duplicated region for block: B:203:0x03a1  */
    /* JADX WARN: Removed duplicated region for block: B:206:0x03aa  */
    /* JADX WARN: Removed duplicated region for block: B:209:0x03b4  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /* JADX WARN: Type inference failed for: r0v31, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r7v3, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r9v21, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r9v33, types: [java.lang.Object, java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object l(com.quizlet.data.model.Y0 r36, kotlin.coroutines.jvm.internal.c r37) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 976
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folderwithcreator.e.l(com.quizlet.data.model.Y0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x00bb A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object m(com.quizlet.ads.c r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r10 = this;
            boolean r0 = r12 instanceof com.quizlet.search.ads.c
            if (r0 == 0) goto L13
            r0 = r12
            com.quizlet.search.ads.c r0 = (com.quizlet.search.ads.c) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.p = r1
            goto L18
        L13:
            com.quizlet.search.ads.c r0 = new com.quizlet.search.ads.c
            r0.<init>(r10, r12)
        L18:
            java.lang.Object r12 = r0.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.p
            java.lang.String r3 = "await(...)"
            r4 = 3
            r5 = 2
            r6 = 1
            if (r2 == 0) goto L52
            if (r2 == r6) goto L45
            if (r2 == r5) goto L37
            if (r2 != r4) goto L2f
            androidx.glance.appwidget.protobuf.Z.e(r12)
            return r12
        L2f:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L37:
            java.util.Map r11 = r0.m
            java.util.Map r11 = (java.util.Map) r11
            com.quizlet.ads.helper.b r2 = r0.l
            com.quizlet.ads.c r5 = r0.k
            com.quizlet.data.repository.folderwithcreator.e r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L96
        L45:
            com.quizlet.ads.helper.b r11 = r0.l
            com.quizlet.ads.c r2 = r0.k
            com.quizlet.data.repository.folderwithcreator.e r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r9 = r2
            r2 = r11
            r11 = r9
            goto L71
        L52:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            java.lang.Object r12 = r10.b
            com.google.mlkit.vision.documentscanner.internal.c r12 = (com.google.mlkit.vision.documentscanner.internal.c) r12
            io.reactivex.rxjava3.internal.operators.flowable.b r12 = r12.g(r11)
            r0.j = r10
            r0.k = r11
            java.lang.Object r2 = r10.d
            com.quizlet.ads.helper.b r2 = (com.quizlet.ads.helper.b) r2
            r0.l = r2
            r0.p = r6
            java.lang.Object r12 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r12, r0)
            if (r12 != r1) goto L70
            goto Lba
        L70:
            r6 = r10
        L71:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r12, r3)
            java.util.Map r12 = (java.util.Map) r12
            java.lang.Object r7 = r6.c
            com.quizlet.ads.b r7 = (com.quizlet.ads.b) r7
            io.reactivex.rxjava3.core.p r7 = r7.a()
            r0.j = r6
            r0.k = r11
            r0.l = r2
            r8 = r12
            java.util.Map r8 = (java.util.Map) r8
            r0.m = r8
            r0.p = r5
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r7, r0)
            if (r5 != r1) goto L92
            goto Lba
        L92:
            r9 = r5
            r5 = r11
            r11 = r12
            r12 = r9
        L96:
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r12, r3)
            java.util.Map r12 = (java.util.Map) r12
            r2.getClass()
            com.google.android.gms.ads.admanager.AdManagerAdRequest r11 = com.quizlet.ads.helper.b.a(r11, r12)
            com.quizlet.search.ads.d r12 = new com.quizlet.search.ads.d
            r2 = 0
            r12.<init>(r6, r5, r11, r2)
            r0.j = r2
            r0.k = r2
            r0.l = r2
            r0.m = r2
            r0.p = r4
            r2 = 10000(0x2710, double:4.9407E-320)
            java.lang.Object r11 = kotlinx.coroutines.E.L(r2, r12, r0)
            if (r11 != r1) goto Lbb
        Lba:
            return r1
        Lbb:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folderwithcreator.e.m(com.quizlet.ads.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x0074  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0091  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:28:0x0086 -> B:30:0x0089). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable n(int r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof com.quizlet.search.ads.e
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.search.ads.e r0 = (com.quizlet.search.ads.e) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.search.ads.e r0 = new com.quizlet.search.ads.e
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            java.util.Iterator r6 = r0.l
            java.util.List r2 = r0.k
            com.quizlet.data.repository.folderwithcreator.e r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L89
        L2d:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.util.ArrayList r7 = new java.util.ArrayList
            r7.<init>()
            if (r6 == r3) goto L5c
            r2 = 2
            if (r6 == r2) goto L4f
            r2 = 3
            if (r6 == r2) goto L48
            kotlin.collections.K r6 = kotlin.collections.K.a
            goto L68
        L48:
            com.quizlet.ads.c r6 = com.quizlet.ads.c.g
            java.util.List r6 = kotlin.collections.A.b(r6)
            goto L68
        L4f:
            com.quizlet.ads.c r6 = com.quizlet.ads.c.e
            com.quizlet.ads.c r2 = com.quizlet.ads.c.f
            com.quizlet.ads.c[] r6 = new com.quizlet.ads.c[]{r6, r2}
            java.util.List r6 = kotlin.collections.B.j(r6)
            goto L68
        L5c:
            com.quizlet.ads.c r6 = com.quizlet.ads.c.c
            com.quizlet.ads.c r2 = com.quizlet.ads.c.d
            com.quizlet.ads.c[] r6 = new com.quizlet.ads.c[]{r6, r2}
            java.util.List r6 = kotlin.collections.B.j(r6)
        L68:
            java.util.Iterator r6 = r6.iterator()
            r4 = r5
            r2 = r7
        L6e:
            boolean r7 = r6.hasNext()
            if (r7 == 0) goto L91
            java.lang.Object r7 = r6.next()
            com.quizlet.ads.c r7 = (com.quizlet.ads.c) r7
            r0.j = r4
            r0.k = r2
            r0.l = r6
            r0.o = r3
            java.lang.Object r7 = r4.m(r7, r0)
            if (r7 != r1) goto L89
            return r1
        L89:
            com.quizlet.search.ads.b r7 = (com.quizlet.search.ads.b) r7
            if (r7 == 0) goto L6e
            r2.add(r7)
            goto L6e
        L91:
            int r6 = r2.size()
            if (r6 != r3) goto La2
            java.lang.Object r6 = kotlin.collections.CollectionsKt.firstOrNull(r2)
            kotlin.Pair r7 = new kotlin.Pair
            r0 = 0
            r7.<init>(r6, r0)
            return r7
        La2:
            java.lang.Object r6 = kotlin.collections.CollectionsKt.firstOrNull(r2)
            java.lang.Object r7 = kotlin.collections.CollectionsKt.V(r2)
            kotlin.Pair r0 = new kotlin.Pair
            r0.<init>(r6, r7)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folderwithcreator.e.n(int, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public Integer o(l lVar, EnumMap enumMap, Function function) {
        boolean zC = lVar.c();
        com.iabtcf.utils.a aVar = (com.iabtcf.utils.a) this.b;
        if (!zC) {
            return (Integer) function.apply(aVar);
        }
        Integer num = (Integer) enumMap.get(lVar);
        if (num != null) {
            return num;
        }
        Integer num2 = (Integer) function.apply(aVar);
        enumMap.put((EnumMap) lVar, (l) num2);
        return num2;
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        boolean z = th instanceof CancellationException;
        androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) this.c;
        if (z) {
            AbstractC3242q6.h(null, iVar.d(new h0(android.support.v4.media.session.a.t(new StringBuilder(), (String) this.d, " cancelled."), th)));
        } else {
            iVar.b(null);
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        androidx.camera.core.impl.utils.futures.i.e(true, (com.google.common.util.concurrent.e) this.b, (androidx.concurrent.futures.i) this.c, T.a());
    }

    public Object p(CharSequence charSequence, int i, int i2, int i3, boolean z, androidx.emoji2.text.p pVar) {
        int i4;
        char c;
        androidx.emoji2.text.s sVar = new androidx.emoji2.text.s((v) ((com.quizlet.data.repository.explanations.textbook.a) this.c).c);
        int iCodePointAt = Character.codePointAt(charSequence, i);
        boolean zD = true;
        int i5 = 0;
        int iCharCount = i;
        loop0: while (true) {
            i4 = iCharCount;
            while (iCharCount < i2 && i5 < i3 && zD) {
                SparseArray sparseArray = sVar.c.a;
                v vVar = sparseArray == null ? null : (v) sparseArray.get(iCodePointAt);
                if (sVar.a == 2) {
                    if (vVar != null) {
                        sVar.c = vVar;
                        sVar.f++;
                    } else {
                        if (iCodePointAt == 65038) {
                            sVar.a();
                        } else if (iCodePointAt != 65039) {
                            v vVar2 = sVar.c;
                            if (vVar2.b != null) {
                                if (sVar.f != 1) {
                                    sVar.d = vVar2;
                                    sVar.a();
                                } else if (sVar.b()) {
                                    sVar.d = sVar.c;
                                    sVar.a();
                                } else {
                                    sVar.a();
                                }
                                c = 3;
                            } else {
                                sVar.a();
                            }
                        }
                        c = 1;
                    }
                    c = 2;
                } else if (vVar == null) {
                    sVar.a();
                    c = 1;
                } else {
                    sVar.a = 2;
                    sVar.c = vVar;
                    sVar.f = 1;
                    c = 2;
                }
                sVar.e = iCodePointAt;
                if (c == 1) {
                    iCharCount = Character.charCount(Character.codePointAt(charSequence, i4)) + i4;
                    if (iCharCount < i2) {
                        iCodePointAt = Character.codePointAt(charSequence, iCharCount);
                    }
                } else if (c == 2) {
                    int iCharCount2 = Character.charCount(iCodePointAt) + iCharCount;
                    if (iCharCount2 < i2) {
                        iCodePointAt = Character.codePointAt(charSequence, iCharCount2);
                    }
                    iCharCount = iCharCount2;
                } else if (c == 3) {
                    if (z || !k(charSequence, i4, iCharCount, sVar.d.b)) {
                        zD = pVar.d(charSequence, i4, iCharCount, sVar.d.b);
                        i5++;
                    }
                }
            }
            break loop0;
        }
        if (sVar.a == 2 && sVar.c.b != null && ((sVar.f > 1 || sVar.b()) && i5 < i3 && zD && (z || !k(charSequence, i4, iCharCount, sVar.c.b)))) {
            pVar.d(charSequence, i4, iCharCount, sVar.c.b);
        }
        return pVar.a();
    }

    public void q() {
        boolean z;
        WriteModeResultsView writeModeResultsView = (WriteModeResultsView) this.d;
        com.quizlet.features.write.base.b bVar = (com.quizlet.features.write.base.b) writeModeResultsView.g;
        com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = bVar.u;
        if (aVar == null || !aVar.d()) {
            z = false;
        } else {
            for (DBSelectedTerm dBSelectedTerm : bVar.u.u) {
                if (!dBSelectedTerm.getDeleted()) {
                    DBTerm dBTerm = (DBTerm) CollectionsKt.N(bVar.u.s, new com.quizlet.eventlogger.features.folder.a(1, Long.valueOf(dBSelectedTerm.getTermId())));
                    if (dBTerm != null && !dBTerm.getDeleted()) {
                        z = true;
                        break;
                    }
                }
            }
            z = false;
        }
        boolean z2 = ((com.quizlet.features.write.base.b) writeModeResultsView.g).r;
        n nVar = (n) this.c;
        ((QButton) (z2 ? nVar.g : nVar.b)).setVisibility(z ? 0 : 8);
        ((Space) nVar.e).setVisibility(z ? 0 : 8);
    }

    public io.reactivex.rxjava3.core.a r(C4127f1 progressReset) {
        Intrinsics.checkNotNullParameter(progressReset, "progressReset");
        com.quizlet.data.repository.progress.c cVar = new com.quizlet.data.repository.progress.c(progressReset.a, progressReset.b, progressReset.c);
        com.google.firebase.crashlytics.internal.settings.b bVar = (com.google.firebase.crashlytics.internal.settings.b) this.b;
        List progressResetIds = A.b(cVar);
        Intrinsics.checkNotNullParameter(progressResetIds, "ids");
        Object value = ((u) bVar.b).getValue();
        Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
        Dao dao = (Dao) value;
        Intrinsics.checkNotNullParameter(progressResetIds, "progressResetIds");
        String strS = progressResetIds.isEmpty() ? "0" : CollectionsKt.S(progressResetIds, " OR ", "(", ")", new com.quizlet.local.ormlite.database.dao.c(), 24);
        io.reactivex.rxjava3.internal.operators.single.g gVarG = com.quizlet.local.ormlite.util.b.b(dao, x.c("\nSELECT * FROM progress_reset\nWHERE " + strS + "\nAND " + com.google.android.gms.internal.mlkit_vision_document_scanner.A.a(true) + "\n    ")).g(com.quizlet.local.ormlite.database.a.a);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        io.reactivex.rxjava3.internal.operators.completable.a aVar = new io.reactivex.rxjava3.internal.operators.completable.a(5, gVarG, new androidx.work.impl.model.e(23, this, progressReset));
        Intrinsics.checkNotNullExpressionValue(aVar, "flatMapCompletable(...)");
        return aVar;
    }

    public Object s(InterfaceC4176w0 interfaceC4176w0, kotlin.coroutines.jvm.internal.c cVar) {
        return E.J((AbstractC5040y) this.d, new com.quizlet.remote.model.metering.b(this, interfaceC4176w0, null), cVar);
    }

    public e(int i) {
        this.a = i;
        switch (i) {
            case 7:
                this.b = new HashMap();
                this.c = new HashMap();
                this.d = C3676n.c;
                break;
        }
    }

    public e(com.quizlet.data.repository.folderwithcreatorinclass.e folderWithCreatorInClassRepository, com.quizlet.data.repository.folderset.c folderSetRepository, androidx.work.impl.model.c dispatcher) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(folderWithCreatorInClassRepository, "folderWithCreatorInClassRepository");
        Intrinsics.checkNotNullParameter(folderSetRepository, "folderSetRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = folderWithCreatorInClassRepository;
        this.c = folderSetRepository;
        this.d = dispatcher;
    }

    public e(androidx.work.impl.model.c userProps, com.quizlet.data.repository.activitycenter.b eligibilityFeature, C4633r factory) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(eligibilityFeature, "eligibilityFeature");
        Intrinsics.checkNotNullParameter(factory, "factory");
        this.b = userProps;
        this.c = eligibilityFeature;
        this.d = factory;
    }

    public e(com.quizlet.remote.service.p service, com.quizlet.quizletandroid.ui.profile.p mapper, AbstractC5040y dispatcher) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = service;
        this.c = mapper;
        this.d = dispatcher;
    }

    public e(com.google.firebase.crashlytics.internal.settings.b dao, ModelIdentityProvider modelIdentityProvider, com.quizlet.shared.usecase.folderstudymaterials.c mapper) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(dao, "dao");
        Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = dao;
        this.c = modelIdentityProvider;
        this.d = mapper;
    }

    public e(com.google.mlkit.vision.documentscanner.internal.c adBidTargetsProvider, com.quizlet.ads.b adTargetsManager, com.quizlet.ads.helper.b adLoaderHelper) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(adBidTargetsProvider, "adBidTargetsProvider");
        Intrinsics.checkNotNullParameter(adTargetsManager, "adTargetsManager");
        Intrinsics.checkNotNullParameter(adLoaderHelper, "adLoaderHelper");
        this.b = adBidTargetsProvider;
        this.c = adTargetsManager;
        this.d = adLoaderHelper;
    }

    public e(List list) {
        this.a = 4;
        this.d = list;
        this.b = new ArrayList(list.size());
        this.c = new ArrayList(list.size());
        for (int i = 0; i < list.size(); i++) {
            ((ArrayList) this.b).add(new com.airbnb.lottie.animation.keyframe.n((List) ((com.airbnb.lottie.model.content.f) list.get(i)).b.b));
            ((ArrayList) this.c).add(((com.airbnb.lottie.model.content.f) list.get(i)).c.j());
        }
    }

    public e(androidx.work.impl.model.e factory, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = factory;
        this.c = networkStatus;
        this.d = logger;
    }

    public e(com.quizlet.features.practicetest.results.usecase.a motivationalMessageUseCase, com.google.firebase.heartbeatinfo.e getDefaultPracticeTestConfigurationUseCase, androidx.work.impl.model.e userHasFreeTrialUseCase) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(motivationalMessageUseCase, "motivationalMessageUseCase");
        Intrinsics.checkNotNullParameter(getDefaultPracticeTestConfigurationUseCase, "getDefaultPracticeTestConfigurationUseCase");
        Intrinsics.checkNotNullParameter(userHasFreeTrialUseCase, "userHasFreeTrialUseCase");
        this.b = motivationalMessageUseCase;
        this.c = userHasFreeTrialUseCase;
        this.d = new com.quizlet.features.practicetest.common.data.l();
    }

    public e(com.iabtcf.utils.a aVar) {
        this.a = 9;
        this.c = new EnumMap(l.class);
        this.d = new EnumMap(l.class);
        this.b = aVar;
    }

    public e(Collection collection) {
        this.a = 5;
        String nonce = UUID.randomUUID().toString();
        Intrinsics.checkNotNullExpressionValue(nonce, "randomUUID().toString()");
        Intrinsics.checkNotNullParameter(nonce, "nonce");
        IntRange intRange = new IntRange(43, 128, 1);
        kotlin.random.d random = kotlin.random.e.a;
        Intrinsics.checkNotNullParameter(intRange, "<this>");
        Intrinsics.checkNotNullParameter(random, "random");
        try {
            int iG = AbstractC3348i.g(random, intRange);
            ArrayList arrayListD0 = CollectionsKt.d0(CollectionsKt.d0(CollectionsKt.d0(CollectionsKt.d0(CollectionsKt.c0(CollectionsKt.e0(new kotlin.ranges.e('a', 'z'), new kotlin.ranges.e('A', 'Z')), new kotlin.ranges.e('0', '9')), '-'), '.'), '_'), '~');
            ArrayList arrayList = new ArrayList(iG);
            for (int i = 0; i < iG; i++) {
                Character ch = (Character) CollectionsKt.f0(arrayListD0, kotlin.random.e.a);
                ch.getClass();
                arrayList.add(ch);
            }
            String codeVerifier = CollectionsKt.S(arrayList, "", null, null, null, 62);
            Intrinsics.checkNotNullParameter(nonce, "nonce");
            Intrinsics.checkNotNullParameter(codeVerifier, "codeVerifier");
            if (((nonce == null || nonce.length() == 0) ? false : !(StringsKt.L(nonce, ' ', 0, false, 6) >= 0)) && K2.c(codeVerifier)) {
                HashSet hashSet = collection != null ? new HashSet(collection) : new HashSet();
                hashSet.add("openid");
                Set setUnmodifiableSet = Collections.unmodifiableSet(hashSet);
                Intrinsics.checkNotNullExpressionValue(setUnmodifiableSet, "unmodifiableSet(permissions)");
                this.b = setUnmodifiableSet;
                this.c = nonce;
                this.d = codeVerifier;
                return;
            }
            throw new IllegalArgumentException("Failed requirement.");
        } catch (IllegalArgumentException e) {
            throw new NoSuchElementException(e.getMessage());
        }
    }

    public e(r rVar) {
        this.a = 2;
        this.b = rVar;
        this.c = new p(6);
        this.d = new androidx.collection.z(10);
    }

    public e(com.google.android.material.motion.b bVar, View view) {
        Object cVar;
        this.a = 8;
        int i = Build.VERSION.SDK_INT;
        if (i >= 34) {
            cVar = new com.google.android.material.motion.e();
        } else {
            cVar = i >= 33 ? new com.google.android.material.motion.c() : null;
        }
        this.b = cVar;
        this.c = bVar;
        this.d = view;
    }

    public e(org.jsoup.select.m mVar) {
        this.a = 19;
        this.b = null;
        this.c = null;
        this.d = mVar;
    }

    public e(com.quizlet.data.repository.explanations.textbook.a aVar, com.quizlet.shared.usecase.folderstudymaterials.d dVar, androidx.emoji2.text.d dVar2, Set set) {
        this.a = 3;
        this.b = dVar;
        this.c = aVar;
        this.d = dVar2;
        if (set.isEmpty()) {
            return;
        }
        Iterator it2 = set.iterator();
        while (it2.hasNext()) {
            int[] iArr = (int[]) it2.next();
            String str = new String(iArr, 0, iArr.length);
            p(str, 0, str.length(), 1, true, new androidx.emoji2.text.r(str));
        }
    }

    public e(WriteModeResultsView writeModeResultsView, n nVar) {
        this.a = 16;
        this.d = writeModeResultsView;
        this.c = nVar;
        this.b = (LinearLayout) nVar.c;
        ((QButton) nVar.g).setOnClickListener(writeModeResultsView.j);
        ((QButton) nVar.b).setOnClickListener(writeModeResultsView.k);
    }
}
