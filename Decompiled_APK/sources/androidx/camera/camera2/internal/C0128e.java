package androidx.camera.camera2.internal;

import android.content.ContentValues;
import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import com.google.android.gms.internal.ads.C2824xF;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.quizletandroid.ui.library.LibraryFragment;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import java.lang.ref.WeakReference;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.camera.camera2.internal.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0128e implements androidx.concurrent.futures.j, com.google.android.datatransport.runtime.scheduling.persistence.e, com.quizlet.qutils.rx.c, com.quizlet.uicommon.ui.common.dialogs.f {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C0128e(long j, Object obj, int i) {
        this.a = i;
        this.b = j;
        this.c = obj;
    }

    @Override // com.quizlet.qutils.rx.c
    public void accept(Object obj) {
        Object obj2 = this.c;
        switch (this.a) {
            case 2:
                String str = LibraryFragment.n;
                LibraryFragment libraryFragment = (LibraryFragment) obj2;
                com.quizlet.features.setpage.e eVar = SetPageActivity.h1;
                Context contextRequireContext = libraryFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                libraryFragment.startActivity(com.quizlet.features.setpage.e.b(eVar, contextRequireContext, this.b, null, null, null, null, false, null, 252));
                break;
            default:
                List<DBTerm> terms = (List) obj;
                String str2 = EditSetFragment.J;
                Intrinsics.checkNotNullParameter(terms, "terms");
                for (DBTerm dBTerm : terms) {
                    if (dBTerm.getId() == this.b) {
                        com.google.firebase.tracing.a aVar = (com.google.firebase.tracing.a) obj2;
                        aVar.getClass();
                        ((C2824xF) ((com.quizlet.quizletandroid.ui.activitycenter.views.i) aVar.b).b).b(dBTerm, (Uri) aVar.c);
                        break;
                    }
                }
                break;
        }
    }

    @Override // com.google.android.datatransport.runtime.scheduling.persistence.e, io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        SQLiteDatabase sQLiteDatabase = (SQLiteDatabase) obj;
        ContentValues contentValues = new ContentValues();
        contentValues.put("next_request_ms", Long.valueOf(this.b));
        com.google.android.datatransport.runtime.i iVar = (com.google.android.datatransport.runtime.i) this.c;
        String str = iVar.a;
        com.google.android.datatransport.d dVar = iVar.c;
        if (sQLiteDatabase.update("transport_contexts", contentValues, "backend_name = ? and priority = ?", new String[]{str, String.valueOf(com.google.android.datatransport.runtime.util.a.a(dVar))}) < 1) {
            contentValues.put("backend_name", iVar.a);
            contentValues.put("priority", Integer.valueOf(com.google.android.datatransport.runtime.util.a.a(dVar)));
            sQLiteDatabase.insert("transport_contexts", null, contentValues);
        }
        return null;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.f
    public void c(com.quizlet.uicommon.ui.common.dialogs.e dialog, int i) {
        DBTerm term;
        DBImage definitionImage;
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
        String str = EditSetFragment.J;
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = ((EditSetFragment) this.c).A;
        if (fVar != null) {
            fVar.m();
            com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar.r.get();
            if (aVar != null) {
                int iH = fVar.h(this.b);
                int i2 = iH == -1 ? -1 : iH + 1;
                if (i2 != -1 && (definitionImage = (term = fVar.j(i2)).getDefinitionImage()) != null) {
                    definitionImage.setDeleted(true);
                    term.setDefinitionImage(null);
                    term.setDefinitionImageId(null);
                    fVar.notifyItemChanged(i2, Integer.valueOf(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR));
                    Intrinsics.checkNotNullParameter(term, "term");
                    Intrinsics.checkNotNullParameter(definitionImage, "definitionImage");
                    WeakReference weakReference = ((EditSetFragment) aVar).x;
                    if (weakReference != null && (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) != null) {
                        com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).y;
                        com.quizlet.infra.legacysyncengine.managers.i iVar2 = iVar.d;
                        iVar2.c(term);
                        iVar2.c(definitionImage);
                        iVar.o.i(new com.quizlet.quizletandroid.ui.setcreation.managers.e(iVar), io.reactivex.rxjava3.internal.functions.d.e);
                        iVar.e.a = false;
                    }
                }
            }
        }
        dialog.dismiss();
    }

    @Override // androidx.concurrent.futures.j
    public Object d(final androidx.concurrent.futures.i iVar) {
        C0137n c0137n = (C0137n) this.c;
        c0137n.getClass();
        final long j = this.b;
        c0137n.h(new InterfaceC0136m() { // from class: androidx.camera.camera2.internal.f
            /* JADX WARN: Removed duplicated region for block: B:13:0x002e  */
            @Override // androidx.camera.camera2.internal.InterfaceC0136m
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public final boolean d(android.hardware.camera2.TotalCaptureResult r5) {
                /*
                    r4 = this;
                    long r0 = r1
                    android.hardware.camera2.CaptureRequest r2 = r5.getRequest()
                    if (r2 != 0) goto L9
                    goto L2e
                L9:
                    android.hardware.camera2.CaptureRequest r5 = r5.getRequest()
                    java.lang.Object r5 = r5.getTag()
                    boolean r2 = r5 instanceof androidx.camera.core.impl.v0
                    if (r2 == 0) goto L2e
                    androidx.camera.core.impl.v0 r5 = (androidx.camera.core.impl.v0) r5
                    android.util.ArrayMap r5 = r5.a
                    java.lang.String r2 = "CameraControlSessionUpdateId"
                    java.lang.Object r5 = r5.get(r2)
                    java.lang.Long r5 = (java.lang.Long) r5
                    if (r5 != 0) goto L24
                    goto L2e
                L24:
                    long r2 = r5.longValue()
                    int r5 = (r2 > r0 ? 1 : (r2 == r0 ? 0 : -1))
                    if (r5 < 0) goto L2e
                    r5 = 1
                    goto L2f
                L2e:
                    r5 = 0
                L2f:
                    if (r5 == 0) goto L39
                    r5 = 0
                    androidx.concurrent.futures.i r0 = r3
                    r0.b(r5)
                    r5 = 1
                    return r5
                L39:
                    r5 = 0
                    return r5
                */
                throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.C0129f.d(android.hardware.camera2.TotalCaptureResult):boolean");
            }
        });
        return "waitForSessionUpdateId:" + j;
    }

    public /* synthetic */ C0128e(Object obj, long j, int i) {
        this.a = i;
        this.c = obj;
        this.b = j;
    }
}
