package com.google.android.gms.internal.mlkit_vision_barcode;

import android.os.Build;
import androidx.compose.runtime.C0814p;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class y7 {
    public static final androidx.glance.appwidget.proto.i a(androidx.glance.k kVar) {
        androidx.glance.appwidget.proto.j jVar;
        androidx.glance.appwidget.proto.a aVar;
        androidx.glance.appwidget.proto.h hVarW = androidx.glance.appwidget.proto.i.w();
        if (kVar instanceof androidx.glance.layout.i) {
            jVar = androidx.glance.appwidget.proto.j.BOX;
        } else {
            boolean z = kVar instanceof androidx.glance.layout.k;
            androidx.glance.appwidget.x0 x0Var = androidx.glance.appwidget.x0.g;
            if (z) {
                jVar = ((androidx.glance.layout.k) kVar).d.c(x0Var) ? androidx.glance.appwidget.proto.j.RADIO_ROW : androidx.glance.appwidget.proto.j.ROW;
            } else if (kVar instanceof androidx.glance.layout.j) {
                jVar = ((androidx.glance.layout.j) kVar).d.c(x0Var) ? androidx.glance.appwidget.proto.j.RADIO_COLUMN : androidx.glance.appwidget.proto.j.COLUMN;
            } else if (kVar instanceof androidx.glance.text.a) {
                jVar = androidx.glance.appwidget.proto.j.TEXT;
            } else if (kVar instanceof androidx.glance.appwidget.lazy.b) {
                jVar = androidx.glance.appwidget.proto.j.LIST_ITEM;
            } else if (kVar instanceof androidx.glance.appwidget.lazy.a) {
                jVar = androidx.glance.appwidget.proto.j.LAZY_COLUMN;
            } else if (kVar instanceof androidx.glance.layout.l) {
                jVar = androidx.glance.appwidget.proto.j.SPACER;
            } else if (kVar instanceof androidx.glance.l) {
                jVar = androidx.glance.appwidget.proto.j.IMAGE;
            } else if (kVar instanceof androidx.glance.appwidget.D) {
                jVar = androidx.glance.appwidget.proto.j.LINEAR_PROGRESS_INDICATOR;
            } else if (kVar instanceof androidx.glance.appwidget.B0) {
                jVar = androidx.glance.appwidget.proto.j.REMOTE_VIEWS_ROOT;
            } else {
                if (!(kVar instanceof androidx.glance.appwidget.E)) {
                    throw new IllegalArgumentException("Unknown element type " + kVar.getClass().getCanonicalName());
                }
                jVar = androidx.glance.appwidget.proto.j.SIZE_BOX;
            }
        }
        hVarW.d();
        androidx.glance.appwidget.proto.i.k((androidx.glance.appwidget.proto.i) hVarW.b, jVar);
        androidx.glance.layout.t tVar = (androidx.glance.layout.t) kVar.a().a(null, androidx.glance.appwidget.q0.B);
        androidx.glance.unit.g gVar = androidx.glance.unit.f.a;
        androidx.glance.appwidget.proto.b bVarC = c(tVar != null ? tVar.a : gVar);
        hVarW.d();
        androidx.glance.appwidget.proto.i.l((androidx.glance.appwidget.proto.i) hVarW.b, bVarC);
        androidx.glance.layout.m mVar = (androidx.glance.layout.m) kVar.a().a(null, androidx.glance.appwidget.q0.C);
        if (mVar != null) {
            gVar = mVar.a;
        }
        androidx.glance.appwidget.proto.b bVarC2 = c(gVar);
        hVarW.d();
        androidx.glance.appwidget.proto.i.m((androidx.glance.appwidget.proto.i) hVarW.b, bVarC2);
        boolean z2 = kVar.a().a(null, androidx.glance.appwidget.q0.z) != null;
        hVarW.d();
        androidx.glance.appwidget.proto.i.r((androidx.glance.appwidget.proto.i) hVarW.b, z2);
        if (kVar.a().a(null, androidx.glance.appwidget.q0.A) != null) {
            hVarW.d();
            androidx.glance.appwidget.proto.i.q((androidx.glance.appwidget.proto.i) hVarW.b);
        }
        if (kVar instanceof androidx.glance.l) {
            androidx.glance.l lVar = (androidx.glance.l) kVar;
            int i = lVar.d;
            if (i == 1) {
                aVar = androidx.glance.appwidget.proto.a.FIT;
            } else if (i == 0) {
                aVar = androidx.glance.appwidget.proto.a.CROP;
            } else {
                if (i != 2) {
                    throw new IllegalStateException(("Unknown content scale " + ((Object) androidx.glance.layout.h.a(lVar.d))).toString());
                }
                aVar = androidx.glance.appwidget.proto.a.FILL_BOUNDS;
            }
            hVarW.d();
            androidx.glance.appwidget.proto.i.p((androidx.glance.appwidget.proto.i) hVarW.b, aVar);
            boolean z3 = !AbstractC3189k7.e(lVar);
            hVarW.d();
            androidx.glance.appwidget.proto.i.t((androidx.glance.appwidget.proto.i) hVarW.b, z3);
            boolean z4 = lVar.c != null;
            hVarW.d();
            androidx.glance.appwidget.proto.i.u((androidx.glance.appwidget.proto.i) hVarW.b, z4);
        } else if (kVar instanceof androidx.glance.layout.j) {
            androidx.glance.appwidget.proto.c cVarE = e(((androidx.glance.layout.j) kVar).f);
            hVarW.d();
            androidx.glance.appwidget.proto.i.n((androidx.glance.appwidget.proto.i) hVarW.b, cVarE);
        } else if (kVar instanceof androidx.glance.layout.k) {
            androidx.glance.appwidget.proto.k kVarD = d(((androidx.glance.layout.k) kVar).f);
            hVarW.d();
            androidx.glance.appwidget.proto.i.o((androidx.glance.appwidget.proto.i) hVarW.b, kVarD);
        } else if (kVar instanceof androidx.glance.layout.i) {
            androidx.glance.layout.i iVar = (androidx.glance.layout.i) kVar;
            androidx.glance.appwidget.proto.c cVarE2 = e(iVar.e.a);
            hVarW.d();
            androidx.glance.appwidget.proto.i.n((androidx.glance.appwidget.proto.i) hVarW.b, cVarE2);
            androidx.glance.appwidget.proto.k kVarD2 = d(iVar.e.b);
            hVarW.d();
            androidx.glance.appwidget.proto.i.o((androidx.glance.appwidget.proto.i) hVarW.b, kVarD2);
        } else if (kVar instanceof androidx.glance.appwidget.lazy.a) {
            androidx.glance.appwidget.proto.c cVarE3 = e(((androidx.glance.appwidget.lazy.a) kVar).e);
            hVarW.d();
            androidx.glance.appwidget.proto.i.n((androidx.glance.appwidget.proto.i) hVarW.b, cVarE3);
        }
        if ((kVar instanceof androidx.glance.m) && !(kVar instanceof androidx.glance.appwidget.lazy.a)) {
            ArrayList arrayList = ((androidx.glance.m) kVar).c;
            ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                arrayList2.add(a((androidx.glance.k) it2.next()));
            }
            hVarW.d();
            androidx.glance.appwidget.proto.i.s((androidx.glance.appwidget.proto.i) hVarW.b, arrayList2);
        }
        return (androidx.glance.appwidget.proto.i) hVarW.b();
    }

    public static com.quizlet.features.notes.data.f b(com.quizlet.features.notes.data.x xVar, C0814p c0814p) {
        com.quizlet.features.notes.data.f fVar;
        com.quizlet.features.notes.data.f fVar2;
        Intrinsics.checkNotNullParameter(xVar, "<this>");
        c0814p.X(-539576257);
        if (xVar.equals(com.quizlet.features.notes.data.g.a)) {
            c0814p.X(71842367);
            String strD = AbstractC3106b5.d(c0814p, R.string.scan_notes_error_generic);
            String strD2 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
            com.quizlet.themes.e.a(c0814p).d.getClass();
            fVar = new com.quizlet.features.notes.data.f(strD, strD2, (String) null, xVar, androidx.compose.animation.core.J0.w(c0814p), 12);
            c0814p.p(false);
        } else if (xVar instanceof com.quizlet.features.notes.data.j) {
            c0814p.X(72166131);
            com.quizlet.features.notes.data.j jVar = (com.quizlet.features.notes.data.j) xVar;
            String strC = AbstractC3106b5.c(R.string.magic_notes_file_too_large, new Object[]{Long.valueOf(jVar.a)}, c0814p);
            String strD3 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
            com.quizlet.themes.e.a(c0814p).d.getClass();
            fVar = new com.quizlet.features.notes.data.f(strC, strD3, (String) null, jVar, androidx.compose.animation.core.J0.w(c0814p), 12);
            c0814p.p(false);
        } else {
            if (xVar.equals(com.quizlet.features.notes.data.k.a)) {
                c0814p.X(72502233);
                String strD4 = AbstractC3106b5.d(c0814p, R.string.magic_notes_file_type_mismatch);
                String strD5 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar2 = new com.quizlet.features.notes.data.f(strD4, strD5, (String) null, xVar, androidx.compose.animation.core.J0.w(c0814p), 12);
                c0814p.p(false);
            } else if (xVar instanceof com.quizlet.features.notes.data.r) {
                c0814p.X(72840939);
                com.quizlet.features.notes.data.r rVar = (com.quizlet.features.notes.data.r) xVar;
                int i = rVar.a;
                String strB = AbstractC3106b5.b(R.plurals.magic_notes_not_enough_characters, i, new Object[]{Integer.valueOf(i)}, c0814p);
                String strD6 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar = new com.quizlet.features.notes.data.f(strB, strD6, (String) null, rVar, androidx.compose.animation.core.J0.w(c0814p), 12);
                c0814p.p(false);
            } else if (xVar instanceof com.quizlet.features.notes.data.t) {
                c0814p.X(73250821);
                com.quizlet.features.notes.data.t tVar = (com.quizlet.features.notes.data.t) xVar;
                String strC2 = AbstractC3106b5.c(R.string.magic_notes_too_many_characters, new Object[]{Integer.valueOf(tVar.a)}, c0814p);
                String strD7 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar = new com.quizlet.features.notes.data.f(strC2, strD7, (String) null, tVar, androidx.compose.animation.core.J0.w(c0814p), 12);
                c0814p.p(false);
            } else if (xVar.equals(com.quizlet.features.notes.data.u.a)) {
                c0814p.X(73603477);
                String strD8 = AbstractC3106b5.d(c0814p, R.string.magic_notes_unable_to_extract_text);
                String strD9 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar2 = new com.quizlet.features.notes.data.f(strD8, strD9, (String) null, xVar, androidx.compose.animation.core.J0.w(c0814p), 12);
                c0814p.p(false);
            } else if (xVar.equals(com.quizlet.features.notes.data.v.a)) {
                c0814p.X(73940726);
                String strD10 = AbstractC3106b5.d(c0814p, R.string.magic_notes_unsupported_file_type);
                String strD11 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar2 = new com.quizlet.features.notes.data.f(strD10, strD11, (String) null, xVar, androidx.compose.animation.core.J0.w(c0814p), 12);
                c0814p.p(false);
            } else if (xVar.equals(com.quizlet.features.notes.data.l.a)) {
                c0814p.X(74274968);
                String strD12 = AbstractC3106b5.d(c0814p, R.string.magic_notes_invalid_youtube_url);
                String strD13 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar2 = new com.quizlet.features.notes.data.f(strD12, strD13, (String) null, xVar, androidx.compose.animation.core.J0.w(c0814p), 12);
                c0814p.p(false);
            } else if (xVar.equals(com.quizlet.features.notes.data.o.a)) {
                c0814p.X(74617580);
                String strD14 = AbstractC3106b5.d(c0814p, R.string.magic_notes_multi_file_upload_files_invalid);
                String strD15 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar2 = new com.quizlet.features.notes.data.f(strD14, strD15, (String) null, xVar, androidx.compose.animation.core.J0.w(c0814p), 12);
                c0814p.p(false);
            } else if (xVar.equals(com.quizlet.features.notes.data.h.a)) {
                c0814p.X(74953217);
                String strD16 = AbstractC3106b5.d(c0814p, R.string.magic_notes_broken_pdf);
                String strD17 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar2 = new com.quizlet.features.notes.data.f(strD16, strD17, (String) null, xVar, androidx.compose.animation.core.J0.w(c0814p), 12);
                c0814p.p(false);
            } else if (xVar.equals(com.quizlet.features.notes.data.n.a)) {
                c0814p.X(75271494);
                String strD18 = AbstractC3106b5.d(c0814p, R.string.scan_notes_error_generic);
                String strD19 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
                String strD20 = AbstractC3106b5.d(c0814p, R.string.scan_notes_error_moderation);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar2 = new com.quizlet.features.notes.data.f(strD18, strD19, strD20, xVar, androidx.compose.animation.core.J0.w(c0814p), 8);
                c0814p.p(false);
            } else if (xVar.equals(com.quizlet.features.notes.data.q.a)) {
                c0814p.X(75671022);
                String strD21 = AbstractC3106b5.d(c0814p, R.string.notes_no_text_error);
                String strD22 = AbstractC3106b5.d(c0814p, R.string.notes_scan_again);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar2 = new com.quizlet.features.notes.data.f(strD21, strD22, (String) null, xVar, androidx.compose.animation.core.J0.w(c0814p), 12);
                c0814p.p(false);
            } else if (xVar instanceof com.quizlet.features.notes.data.s) {
                c0814p.X(75979565);
                String strD23 = AbstractC3106b5.d(c0814p, R.string.scan_notes_private_error);
                String strD24 = AbstractC3106b5.d(c0814p, R.string.scan_notes_private_error_description);
                com.quizlet.features.notes.data.s sVar = (com.quizlet.features.notes.data.s) xVar;
                fVar = new com.quizlet.features.notes.data.f(strD23, AbstractC3106b5.d(c0814p, R.string.scan_notes_create_your_magic_notes_button), strD24, sVar.a, sVar, com.quizlet.themes.e.a(c0814p).d.y(c0814p));
                c0814p.p(false);
            } else if (xVar instanceof com.quizlet.features.notes.data.i) {
                c0814p.X(76443449);
                String strD25 = AbstractC3106b5.d(c0814p, R.string.scan_notes_does_not_exist_error);
                String strD26 = AbstractC3106b5.d(c0814p, R.string.scan_notes_does_not_exist_error_description);
                String strD27 = AbstractC3106b5.d(c0814p, R.string.scan_notes_create_your_magic_notes_button);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                com.quizlet.features.notes.data.i iVar = (com.quizlet.features.notes.data.i) xVar;
                fVar = new com.quizlet.features.notes.data.f(strD25, strD27, strD26, iVar.a, iVar, androidx.compose.animation.core.J0.w(c0814p));
                c0814p.p(false);
            } else if (xVar.equals(com.quizlet.features.notes.data.p.a)) {
                c0814p.X(76924662);
                String strD28 = AbstractC3106b5.d(c0814p, R.string.scan_notes_no_internet_error);
                String strD29 = AbstractC3106b5.d(c0814p, R.string.scan_notes_no_internet_error_description);
                String strD30 = AbstractC3106b5.d(c0814p, R.string.scan_notes_refresh_button);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar2 = new com.quizlet.features.notes.data.f(strD28, strD30, strD29, xVar, androidx.compose.animation.core.J0.w(c0814p), 8);
                c0814p.p(false);
            } else if (xVar.equals(com.quizlet.features.notes.data.w.a)) {
                c0814p.X(77352152);
                String strD31 = AbstractC3106b5.d(c0814p, R.string.scan_notes_upload_limit_reached);
                String strD32 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar2 = new com.quizlet.features.notes.data.f(strD31, strD32, (String) null, xVar, androidx.compose.animation.core.J0.w(c0814p), 12);
                c0814p.p(false);
            } else {
                if (!(xVar instanceof com.quizlet.features.notes.data.m)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-690414528, c0814p, false);
                }
                c0814p.X(77685619);
                com.quizlet.features.notes.data.m mVar = (com.quizlet.features.notes.data.m) xVar;
                String strC3 = AbstractC3106b5.c(R.string.scan_notes_file_size_error, new Object[]{mVar.a}, c0814p);
                String strD33 = AbstractC3106b5.d(c0814p, R.string.magic_notes_back_to_upload);
                com.quizlet.themes.e.a(c0814p).d.getClass();
                fVar = new com.quizlet.features.notes.data.f(strC3, strD33, (String) null, mVar, androidx.compose.animation.core.J0.w(c0814p), 12);
                c0814p.p(false);
            }
            fVar = fVar2;
        }
        c0814p.p(false);
        return fVar;
    }

    public static final androidx.glance.appwidget.proto.b c(androidx.glance.unit.g gVar) {
        if (Build.VERSION.SDK_INT >= 31) {
            return androidx.glance.appwidget.O0.a.a(gVar);
        }
        Object obj = androidx.glance.appwidget.r0.a;
        if (gVar instanceof androidx.glance.unit.c) {
            return androidx.glance.appwidget.proto.b.EXACT;
        }
        if (gVar instanceof androidx.glance.unit.f) {
            return androidx.glance.appwidget.proto.b.WRAP;
        }
        if (gVar instanceof androidx.glance.unit.e) {
            return androidx.glance.appwidget.proto.b.FILL;
        }
        if (gVar instanceof androidx.glance.unit.d) {
            return androidx.glance.appwidget.proto.b.EXPAND;
        }
        throw new IllegalStateException("After resolution, no other type should be present");
    }

    public static final androidx.glance.appwidget.proto.k d(int i) {
        if (i == 0) {
            return androidx.glance.appwidget.proto.k.TOP;
        }
        if (i == 1) {
            return androidx.glance.appwidget.proto.k.CENTER_VERTICALLY;
        }
        if (i == 2) {
            return androidx.glance.appwidget.proto.k.BOTTOM;
        }
        throw new IllegalStateException(("unknown vertical alignment " + ((Object) androidx.glance.layout.b.b(i))).toString());
    }

    public static final androidx.glance.appwidget.proto.c e(int i) {
        if (i == 0) {
            return androidx.glance.appwidget.proto.c.START;
        }
        if (i == 1) {
            return androidx.glance.appwidget.proto.c.CENTER_HORIZONTALLY;
        }
        if (i == 2) {
            return androidx.glance.appwidget.proto.c.END;
        }
        throw new IllegalStateException(("unknown horizontal alignment " + ((Object) androidx.glance.layout.a.b(i))).toString());
    }

    public static boolean f(io.reactivex.rxjava3.core.k kVar, io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.functions.h hVar) {
        if (!(kVar instanceof io.reactivex.rxjava3.functions.j)) {
            return false;
        }
        try {
            Object obj = ((io.reactivex.rxjava3.functions.j) kVar).get();
            if (obj == null) {
                io.reactivex.rxjava3.internal.disposables.b.a(lVar);
                return true;
            }
            try {
                Object objApply = hVar.apply(obj);
                Objects.requireNonNull(objApply, "The mapper returned a null ObservableSource");
                io.reactivex.rxjava3.core.k kVar2 = (io.reactivex.rxjava3.core.k) objApply;
                if (!(kVar2 instanceof io.reactivex.rxjava3.functions.j)) {
                    kVar2.c(lVar);
                    return true;
                }
                try {
                    Object obj2 = ((io.reactivex.rxjava3.functions.j) kVar2).get();
                    if (obj2 == null) {
                        io.reactivex.rxjava3.internal.disposables.b.a(lVar);
                        return true;
                    }
                    io.reactivex.rxjava3.internal.operators.observable.k0 k0Var = new io.reactivex.rxjava3.internal.operators.observable.k0(lVar, obj2);
                    lVar.a(k0Var);
                    k0Var.run();
                    return true;
                } catch (Throwable th) {
                    x7.b(th);
                    io.reactivex.rxjava3.internal.disposables.b.d(th, lVar);
                    return true;
                }
            } catch (Throwable th2) {
                x7.b(th2);
                io.reactivex.rxjava3.internal.disposables.b.d(th2, lVar);
                return true;
            }
        } catch (Throwable th3) {
            x7.b(th3);
            io.reactivex.rxjava3.internal.disposables.b.d(th3, lVar);
            return true;
        }
    }
}
