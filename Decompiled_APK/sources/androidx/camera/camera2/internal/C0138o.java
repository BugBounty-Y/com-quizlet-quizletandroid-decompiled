package androidx.camera.camera2.internal;

import android.content.Context;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraManager;
import androidx.camera.camera2.internal.compat.CameraAccessExceptionCompat;
import androidx.camera.core.C0192o;
import androidx.camera.core.CameraUnavailableException;
import androidx.camera.core.InitializationException;
import androidx.camera.core.impl.C0160b;
import androidx.camera.core.impl.InterfaceC0183w;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBGroupSetFields;
import com.quizlet.db.data.models.persisted.fields.DBUserStudyableFields;
import com.quizlet.generated.enums.G1;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.camera.camera2.internal.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0138o {
    public final long a;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final Object f;
    public Serializable g;
    public final Object h;
    public final Object i;

    public C0138o(com.quizlet.infra.legacysyncengine.net.c loader, long j, long j2, io.ktor.client.plugins.api.d getStudySetsWithCreatorAndClassificationUseCase, com.quizlet.shared.usecase.srs.a localStudySetMapper) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(getStudySetsWithCreatorAndClassificationUseCase, "getStudySetsWithCreatorAndClassificationUseCase");
        Intrinsics.checkNotNullParameter(localStudySetMapper, "localStudySetMapper");
        this.a = j;
        this.b = getStudySetsWithCreatorAndClassificationUseCase;
        this.c = localStudySetMapper;
        Intrinsics.checkNotNullParameter(loader, "loader");
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.GROUP_SET);
        bVar.b(Long.valueOf(j), DBGroupSetFields.SET);
        this.d = new com.quizlet.features.infra.studysetting.datasource.a(loader, bVar.a());
        this.e = new com.quizlet.features.infra.studysetting.datasource.a(loader, j, j2, G1.SET);
        Intrinsics.checkNotNullParameter(loader, "loader");
        com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.USER_STUDYABLE);
        bVar2.b(Long.valueOf(j), DBUserStudyableFields.SET);
        bVar2.b(Long.valueOf(j2), DBUserStudyableFields.PERSON);
        bVar2.b(Long.valueOf(r7.b()), DBUserStudyableFields.STUDYABLE_TYPE);
        this.f = new com.quizlet.features.infra.studysetting.datasource.a(loader, bVar2.a());
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        Intrinsics.checkNotNullExpressionValue(dVar, "empty(...)");
        this.g = dVar;
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.h = dVarZ;
        this.i = com.google.android.gms.measurement.internal.Z.f("create(...)");
    }

    public C a(String str) throws CameraUnavailableException {
        if (!((ArrayList) this.g).contains(str)) {
            throw new IllegalArgumentException("The given camera id is not on the available camera id list.");
        }
        F fB = b(str);
        C0160b c0160b = (C0160b) this.d;
        Executor executor = c0160b.a;
        return new C((Context) this.b, (androidx.camera.camera2.internal.compat.q) this.f, str, fB, (androidx.camera.camera2.internal.concurrent.a) this.c, (androidx.camera.core.impl.D) this.e, executor, c0160b.b, (W) this.h, this.a);
    }

    public F b(String str) throws CameraUnavailableException {
        HashMap map = (HashMap) this.i;
        try {
            F f = (F) map.get(str);
            if (f != null) {
                return f;
            }
            F f2 = new F((androidx.camera.camera2.internal.compat.q) this.f, str);
            map.put(str, f2);
            return f2;
        } catch (CameraAccessExceptionCompat e) {
            throw new CameraUnavailableException(e);
        }
    }

    public C0138o(Context context, C0160b c0160b, C0192o c0192o, long j) throws InitializationException, CameraAccessExceptionCompat {
        String strE;
        this.i = new HashMap();
        this.b = context;
        this.d = c0160b;
        androidx.camera.camera2.internal.compat.q qVarA = androidx.camera.camera2.internal.compat.q.a(context, c0160b.b);
        this.f = qVarA;
        this.h = W.b(context);
        try {
            ArrayList arrayList = new ArrayList();
            androidx.compose.foundation.text.input.internal.u uVar = qVarA.a;
            uVar.getClass();
            try {
                List<String> listAsList = Arrays.asList(((CameraManager) uVar.b).getCameraIdList());
                if (c0192o == null) {
                    Iterator it2 = listAsList.iterator();
                    while (it2.hasNext()) {
                        arrayList.add((String) it2.next());
                    }
                } else {
                    try {
                        strE = com.facebook.appevents.ml.f.e(qVarA, c0192o.b(), listAsList);
                    } catch (IllegalStateException unused) {
                        strE = null;
                    }
                    ArrayList arrayList2 = new ArrayList();
                    for (String str : listAsList) {
                        if (!str.equals(strE)) {
                            arrayList2.add(b(str));
                        }
                    }
                    Iterator it3 = c0192o.a(arrayList2).iterator();
                    while (it3.hasNext()) {
                        arrayList.add(((InterfaceC0183w) it3.next()).c());
                    }
                }
                ArrayList arrayList3 = new ArrayList();
                Iterator it4 = arrayList.iterator();
                while (it4.hasNext()) {
                    String str2 = (String) it4.next();
                    if (!str2.equals("0") && !str2.equals("1")) {
                        if (com.facebook.appevents.internal.d.d((androidx.camera.camera2.internal.compat.q) this.f, str2)) {
                            arrayList3.add(str2);
                        } else {
                            AbstractC3053s1.f(3, "Camera2CameraFactory");
                        }
                    } else {
                        arrayList3.add(str2);
                    }
                }
                this.g = arrayList3;
                androidx.camera.camera2.internal.concurrent.a aVar = new androidx.camera.camera2.internal.concurrent.a((androidx.camera.camera2.internal.compat.q) this.f);
                this.c = aVar;
                androidx.camera.core.impl.D d = new androidx.camera.core.impl.D(aVar);
                this.e = d;
                ((ArrayList) aVar.c).add(d);
                this.a = j;
            } catch (CameraAccessException e) {
                throw new CameraAccessExceptionCompat(e);
            }
        } catch (CameraAccessExceptionCompat e2) {
            throw new InitializationException(new CameraUnavailableException(e2));
        } catch (CameraUnavailableException e3) {
            throw new InitializationException(e3);
        }
    }
}
