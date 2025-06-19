package androidx.compose.foundation.text.input.internal;

import android.content.Context;
import android.graphics.ImageDecoder;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.os.Handler;
import android.view.ActionMode;
import android.view.Menu;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import androidx.appcompat.app.C0062s;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.C0144v;
import androidx.camera.camera2.internal.C0145w;
import androidx.camera.camera2.internal.compat.CameraAccessExceptionCompat;
import androidx.camera.core.impl.y0;
import androidx.cardview.widget.CardView;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.core.view.C1043d0;
import androidx.core.view.J;
import androidx.core.view.V;
import androidx.lifecycle.m0;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.measurement.internal.Z;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.quizlet.data.model.C4135i0;
import com.quizlet.data.model.D0;
import com.quizlet.data.model.I0;
import com.quizlet.data.model.L0;
import com.quizlet.data.model.P0;
import com.quizlet.data.model.S;
import com.quizlet.data.model.Z0;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBDiagramShapeFields;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import com.quizlet.generated.enums.C4531x0;
import com.quizlet.generated.enums.EnumC4533y0;
import com.quizlet.infra.legacysyncengine.models.identity.QueryIdFieldChangeMapper;
import com.quizlet.remote.model.practicetests.PracticeTestCourse;
import com.quizlet.remote.model.practicetests.PracticeTestSchool;
import com.quizlet.remote.model.practicetests.PracticeTestsQuestionResponse;
import com.quizlet.remote.model.practicetests.QuestionBankMetadataResponse;
import com.quizlet.remote.model.practicetests.QuestionBankPreview;
import com.quizlet.remote.model.practicetests.RemoteQuestionBankPreviewResponse;
import com.quizlet.remote.model.user.RemoteFullUser;
import com.quizlet.remote.service.G;
import com.quizlet.remote.service.InterfaceC4777d;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;
import retrofit2.K;
import retrofit2.L;

/* loaded from: classes.dex */
public class u implements com.google.android.gms.ads.internal.util.client.b, OnCompleteListener, io.reactivex.rxjava3.functions.h, com.quizlet.mapper.a {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    public static com.bumptech.glide.load.resource.bitmap.A e(ImageDecoder.Source source, int i, int i2, com.bumptech.glide.load.h hVar) throws IOException {
        Drawable drawableDecodeDrawable = ImageDecoder.decodeDrawable(source, new com.bumptech.glide.load.resource.c(i, i2, hVar));
        if (com.bumptech.glide.load.resource.a.w(drawableDecodeDrawable)) {
            return new com.bumptech.glide.load.resource.bitmap.A(com.bumptech.glide.load.resource.a.k(drawableDecodeDrawable), 2);
        }
        throw new IOException("Received unexpected drawable type for animated image, failing: " + drawableDecodeDrawable);
    }

    @Override // com.quizlet.mapper.a
    public Object a(Object obj) {
        RemoteQuestionBankPreviewResponse input = (RemoteQuestionBankPreviewResponse) obj;
        Intrinsics.checkNotNullParameter(input, "input");
        QuestionBankPreview questionBankPreview = (QuestionBankPreview) CollectionsKt.L(input.d.a);
        S s = (S) ((com.quizlet.quizletandroid.ui.profile.b) this.c).a(CollectionsKt.L(input.d.b));
        ArrayList arrayList = new ArrayList();
        Iterator it2 = questionBankPreview.d.iterator();
        while (it2.hasNext()) {
            arrayList.add(((com.quizlet.local.ormlite.models.term.b) this.b).a((PracticeTestsQuestionResponse) it2.next()));
        }
        PracticeTestCourse practiceTestCourse = questionBankPreview.f;
        L0 l0 = practiceTestCourse != null ? new L0(practiceTestCourse.a, practiceTestCourse.b) : null;
        PracticeTestSchool practiceTestSchool = questionBankPreview.g;
        Z0 z0 = practiceTestSchool != null ? new Z0(practiceTestSchool.a, practiceTestSchool.b) : null;
        RemoteFullUser remoteFullUser = questionBankPreview.h;
        C4135i0 c4135i0D = remoteFullUser != null ? com.quizlet.quizletandroid.managers.upgrade.a.d(remoteFullUser) : null;
        Map map = questionBankPreview.k;
        LinkedHashMap linkedHashMap = new LinkedHashMap(U.a(map.size()));
        for (Map.Entry entry : map.entrySet()) {
            C4531x0 c4531x0 = EnumC4533y0.Companion;
            String str = (String) entry.getKey();
            c4531x0.getClass();
            linkedHashMap.put(C4531x0.a(str), entry.getValue());
        }
        QuestionBankMetadataResponse questionBankMetadataResponse = questionBankPreview.i;
        return new P0(questionBankPreview.a, questionBankPreview.b, arrayList, questionBankPreview.e, l0, z0, c4135i0D, linkedHashMap, questionBankMetadataResponse != null ? questionBankMetadataResponse.a : null, questionBankPreview.j, s);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 17:
                Throwable error = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error, "error");
                ((org.slf4j.b) ((com.quizlet.data.repository.progress.b) this.b).c).c("Error saving progress reset data to local storage", error);
                return (I0) this.c;
            case 18:
                Long userId = (Long) obj;
                Intrinsics.checkNotNullParameter(userId, "userId");
                com.quizlet.explanations.textbook.tableofcontents.viewmodel.b bVar = (com.quizlet.explanations.textbook.tableofcontents.viewmodel.b) this.b;
                return bVar.e.u(userId.longValue(), (D0) this.c, bVar.c);
            case 19:
            case 20:
            default:
                Throwable it2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return io.reactivex.rxjava3.core.i.k(G.b((G) this.b, (L) ((com.quizlet.data.repository.folderset.c) this.c).b, it2));
            case 21:
                Intrinsics.checkNotNullParameter((Boolean) obj, "it");
                List list = (List) this.b;
                Intrinsics.d(list);
                return AbstractC3771z.c((com.quizlet.local.ormlite.models.folder.a) ((com.quizlet.local.ormlite.models.bookmark.a) this.c).c, list);
            case EventType.WINDOW_STATE /* 22 */:
                K it3 = (K) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return io.ktor.client.plugins.api.d.g((io.ktor.client.plugins.api.d) this.b, (String) this.c, it3);
            case EventType.AUDIO /* 23 */:
                LoggedInUserStatus s = (LoggedInUserStatus) obj;
                Intrinsics.checkNotNullParameter(s, "s");
                DBUser currentUser = s.getCurrentUser();
                return (!s.isLoggedIn() || currentUser == null) ? this.c : ((Function1) this.b).invoke(currentUser);
            case EventType.VIDEO /* 24 */:
                Intrinsics.checkNotNullParameter((File) obj, "<unused var>");
                com.quizlet.infra.legacysyncengine.orm.b bVar2 = new com.quizlet.infra.legacysyncengine.orm.b(Models.DIAGRAM_SHAPE);
                bVar2.b(Long.valueOf(((com.quizlet.quizletandroid.data.management.a) this.b).a.getId()), DBDiagramShapeFields.SET_ID);
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar2.a();
                Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
                com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) this.c;
                return new io.reactivex.rxjava3.internal.operators.maybe.e(((com.google.android.datatransport.cct.internal.s) sVar.e).h(((QueryIdFieldChangeMapper) sVar.d).convertStaleLocalIds(aVarA)).f(), 3);
        }
    }

    public void b(Object obj, String str) {
        int length = str.length();
        String strValueOf = String.valueOf(obj);
        ((ArrayList) this.b).add(AbstractC0147y.g(new StringBuilder(length + 1 + strValueOf.length()), str, SimpleComparison.EQUAL_TO_OPERATION, strValueOf));
    }

    public boolean c(androidx.work.impl.model.j id) {
        boolean zContainsKey;
        Intrinsics.checkNotNullParameter(id, "id");
        synchronized (this.c) {
            y0 y0Var = (y0) this.b;
            Intrinsics.checkNotNullParameter(id, "id");
            zContainsKey = y0Var.a.containsKey(id);
        }
        return zContainsKey;
    }

    public com.quizlet.data.repository.metering.j d(m0 savedStateHandle) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        com.quizlet.features.infra.basestudy.manager.f studyModeManager = ((com.quizlet.features.infra.basestudy.manager.a) this.b).a(savedStateHandle);
        com.google.firebase.messaging.p pVar = (com.google.firebase.messaging.p) this.c;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        com.quizlet.data.repository.folderset.c matchSettingsManager = new com.quizlet.data.repository.folderset.c((com.facebook.z) pVar.b, AbstractC3249r5.b(savedStateHandle).a);
        Intrinsics.checkNotNullParameter(studyModeManager, "studyModeManager");
        Intrinsics.checkNotNullParameter(matchSettingsManager, "matchSettingsManager");
        com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j();
        jVar.a = studyModeManager;
        jVar.b = matchSettingsManager;
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        Intrinsics.checkNotNullExpressionValue(dVar, "empty(...)");
        jVar.c = dVar;
        jVar.d = Z.f("create(...)");
        jVar.c = (AtomicReference) studyModeManager.c().u(new com.quizlet.analytics.marketing.e(jVar, 6), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
        studyModeManager.m();
        return jVar;
    }

    public CameraCharacteristics f(String str) throws CameraAccessExceptionCompat {
        try {
            return ((CameraManager) this.b).getCameraCharacteristics(str);
        } catch (CameraAccessException e) {
            throw new CameraAccessExceptionCompat(e);
        }
    }

    public Set g() {
        return Collections.EMPTY_SET;
    }

    public File h() {
        if (((File) this.b) == null) {
            synchronized (this) {
                try {
                    if (((File) this.b) == null) {
                        com.google.firebase.h hVar = (com.google.firebase.h) this.c;
                        hVar.a();
                        this.b = new File(hVar.a.getFilesDir(), "PersistedInstallation." + ((com.google.firebase.h) this.c).d() + ".json");
                    }
                } finally {
                }
            }
        }
        return (File) this.b;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, kotlin.k] */
    public InputMethodManager i() {
        return (InputMethodManager) this.c.getValue();
    }

    public androidx.compose.ui.layout.K j() {
        return (androidx.compose.ui.layout.K) ((androidx.compose.runtime.L0) ((InterfaceC0773a0) this.c)).getValue();
    }

    public void k(com.google.firebase.installations.local.a aVar) throws JSONException, IOException {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("Fid", aVar.a);
            jSONObject.put("Status", AbstractC0147y.k(aVar.b));
            jSONObject.put("AuthToken", aVar.c);
            jSONObject.put("RefreshToken", aVar.d);
            jSONObject.put("TokenCreationEpochInSecs", aVar.f);
            jSONObject.put("ExpiresInSecs", aVar.e);
            jSONObject.put("FisError", aVar.g);
            com.google.firebase.h hVar = (com.google.firebase.h) this.c;
            hVar.a();
            File fileCreateTempFile = File.createTempFile("PersistedInstallation", "tmp", hVar.a.getFilesDir());
            FileOutputStream fileOutputStream = new FileOutputStream(fileCreateTempFile);
            fileOutputStream.write(jSONObject.toString().getBytes("UTF-8"));
            fileOutputStream.close();
            if (fileCreateTempFile.renameTo(h())) {
            } else {
                throw new IOException("unable to rename the tmpfile to PersistedInstallation");
            }
        } catch (IOException | JSONException unused) {
        }
    }

    public void l(androidx.appcompat.view.b bVar) {
        androidx.work.impl.model.i iVar = (androidx.work.impl.model.i) this.b;
        ((ActionMode.Callback) iVar.b).onDestroyActionMode(iVar.b(bVar));
        androidx.appcompat.app.B b = (androidx.appcompat.app.B) this.c;
        if (b.w != null) {
            b.l.getDecorView().removeCallbacks(b.x);
        }
        if (b.v != null) {
            C1043d0 c1043d0 = b.y;
            if (c1043d0 != null) {
                c1043d0.b();
            }
            C1043d0 c1043d0A = V.a(b.v);
            c1043d0A.a(DefinitionKt.NO_Float_VALUE);
            b.y = c1043d0A;
            c1043d0A.d(new C0062s(this, 2));
        }
        b.u = null;
        ViewGroup viewGroup = b.A;
        WeakHashMap weakHashMap = V.a;
        J.c(viewGroup);
        b.J();
    }

    public boolean m(androidx.appcompat.view.b bVar, androidx.appcompat.view.menu.n nVar) {
        ViewGroup viewGroup = ((androidx.appcompat.app.B) this.c).A;
        WeakHashMap weakHashMap = V.a;
        J.c(viewGroup);
        androidx.work.impl.model.i iVar = (androidx.work.impl.model.i) this.b;
        androidx.appcompat.view.f fVarB = iVar.b(bVar);
        androidx.collection.V v = (androidx.collection.V) iVar.e;
        Menu c = (Menu) v.get(nVar);
        if (c == null) {
            c = new androidx.appcompat.view.menu.C((Context) iVar.c, nVar);
            v.put(nVar, c);
        }
        return ((ActionMode.Callback) iVar.b).onPrepareActionMode(fVarB, c);
    }

    public void n(String str, androidx.camera.core.impl.utils.executor.k kVar, CameraDevice.StateCallback stateCallback) {
        kVar.getClass();
        stateCallback.getClass();
        try {
            ((CameraManager) this.b).openCamera(str, new C0144v(kVar, stateCallback), (Handler) ((com.quizlet.data.repository.widget.b) this.c).c);
        } catch (CameraAccessException e) {
            throw new CameraAccessExceptionCompat(e);
        }
    }

    public com.google.firebase.installations.local.a o() throws IOException {
        JSONObject jSONObject;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] bArr = new byte[16384];
        try {
            FileInputStream fileInputStream = new FileInputStream(h());
            while (true) {
                try {
                    int i = fileInputStream.read(bArr, 0, 16384);
                    if (i < 0) {
                        break;
                    }
                    byteArrayOutputStream.write(bArr, 0, i);
                } finally {
                }
            }
            jSONObject = new JSONObject(byteArrayOutputStream.toString());
            fileInputStream.close();
        } catch (IOException | JSONException unused) {
            jSONObject = new JSONObject();
        }
        String strOptString = jSONObject.optString("Fid", null);
        int iOptInt = jSONObject.optInt("Status", 0);
        String strOptString2 = jSONObject.optString("AuthToken", null);
        String strOptString3 = jSONObject.optString("RefreshToken", null);
        long jOptLong = jSONObject.optLong("TokenCreationEpochInSecs", 0L);
        long jOptLong2 = jSONObject.optLong("ExpiresInSecs", 0L);
        String strOptString4 = jSONObject.optString("FisError", null);
        int i2 = AbstractC0147y.n(5)[iOptInt];
        if (i2 == 0) {
            throw new NullPointerException("Null registrationStatus");
        }
        String str = i2 == 0 ? " registrationStatus" : "";
        if (str.isEmpty()) {
            return new com.google.firebase.installations.local.a(strOptString, i2, strOptString2, strOptString3, jOptLong2, jOptLong, strOptString4);
        }
        throw new IllegalStateException("Missing required properties:".concat(str));
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public void onComplete(Task task) {
        com.google.android.play.core.review.internal.j jVar = (com.google.android.play.core.review.internal.j) this.b;
        com.google.android.gms.tasks.f fVar = (com.google.android.gms.tasks.f) this.c;
        synchronized (jVar.f) {
            jVar.e.remove(fVar);
        }
    }

    public void p(androidx.camera.core.impl.utils.executor.k kVar, C0145w c0145w) {
        androidx.camera.camera2.internal.compat.p pVar;
        com.quizlet.data.repository.widget.b bVar = (com.quizlet.data.repository.widget.b) this.c;
        synchronized (((HashMap) bVar.b)) {
            try {
                pVar = (androidx.camera.camera2.internal.compat.p) ((HashMap) bVar.b).get(c0145w);
                if (pVar == null) {
                    pVar = new androidx.camera.camera2.internal.compat.p(kVar, c0145w);
                    ((HashMap) bVar.b).put(c0145w, pVar);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        ((CameraManager) this.b).registerAvailabilityCallback(pVar, (Handler) bVar.c);
    }

    public androidx.work.impl.j q(androidx.work.impl.model.j id) {
        androidx.work.impl.j jVarF;
        Intrinsics.checkNotNullParameter(id, "id");
        synchronized (this.c) {
            jVarF = ((y0) this.b).f(id);
        }
        return jVarF;
    }

    public List r(String workSpecId) {
        List listG;
        Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
        synchronized (this.c) {
            listG = ((y0) this.b).g(workSpecId);
        }
        return listG;
    }

    public void s(int i, int i2, int i3, int i4) {
        CardView cardView = (CardView) this.c;
        cardView.d.set(i, i2, i3, i4);
        Rect rect = cardView.c;
        super/*android.view.View*/.setPadding(i + rect.left, i2 + rect.top, i3 + rect.right, i4 + rect.bottom);
    }

    public androidx.work.impl.j t(androidx.work.impl.model.j id) {
        androidx.work.impl.j jVarH;
        Intrinsics.checkNotNullParameter(id, "id");
        synchronized (this.c) {
            jVarH = ((y0) this.b).h(id);
        }
        return jVarH;
    }

    public String toString() {
        switch (this.a) {
            case 10:
                StringBuilder sb = new StringBuilder(100);
                sb.append(this.c.getClass().getSimpleName());
                sb.append('{');
                ArrayList arrayList = (ArrayList) this.b;
                int size = arrayList.size();
                for (int i = 0; i < size; i++) {
                    sb.append((String) arrayList.get(i));
                    if (i < size - 1) {
                        sb.append(", ");
                    }
                }
                sb.append('}');
                return sb.toString();
            default:
                return super.toString();
        }
    }

    public void u(CameraManager.AvailabilityCallback availabilityCallback) {
        androidx.camera.camera2.internal.compat.p pVar;
        if (availabilityCallback != null) {
            com.quizlet.data.repository.widget.b bVar = (com.quizlet.data.repository.widget.b) this.c;
            synchronized (((HashMap) bVar.b)) {
                pVar = (androidx.camera.camera2.internal.compat.p) ((HashMap) bVar.b).remove(availabilityCallback);
            }
        } else {
            pVar = null;
        }
        if (pVar != null) {
            synchronized (pVar.c) {
                pVar.d = true;
            }
        }
        ((CameraManager) this.b).unregisterAvailabilityCallback(pVar);
    }

    @Override // com.google.android.gms.ads.internal.util.client.b
    public com.google.android.gms.ads.internal.util.client.j zza(String str) {
        com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        new com.google.android.gms.ads.internal.util.t((Context) this.b, (String) this.c, str, null).R();
        return com.google.android.gms.ads.internal.util.client.j.a;
    }

    public /* synthetic */ u(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    public /* synthetic */ u(Object obj, int i) {
        this.a = i;
        this.c = obj;
    }

    public /* synthetic */ u(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public /* synthetic */ u(Object obj) {
        this.a = 10;
        this.c = obj;
        this.b = new ArrayList();
    }

    public u(com.quizlet.quizletandroid.ui.group.data.b dataSourceFactory) {
        this.a = 26;
        Intrinsics.checkNotNullParameter(dataSourceFactory, "dataSourceFactory");
        this.b = dataSourceFactory;
    }

    public u(InterfaceC4777d dataSource, com.quizlet.quizletandroid.ui.joincontenttofolder.i mapper) {
        this.a = 27;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = dataSource;
        this.c = mapper;
    }

    public u(com.quizlet.data.repository.achievements.h repository, UserInfoCache userInfoCache) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        this.b = repository;
        this.c = userInfoCache;
    }

    public u(com.quizlet.infra.legacysyncengine.net.c loader) {
        this.a = 25;
        Intrinsics.checkNotNullParameter(loader, "loader");
        this.b = loader;
    }

    public u(com.quizlet.data.repository.set.f recommendedSetRepository, androidx.work.impl.model.c dispatcher) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(recommendedSetRepository, "recommendedSetRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = recommendedSetRepository;
        this.c = dispatcher;
    }

    public u(com.quizlet.quizletandroid.managers.upgrade.a remoteFullUserMapper, com.quizlet.local.ormlite.models.term.b practiceTestsQuestionMapper, com.quizlet.quizletandroid.ui.profile.b entitlementDataMapper) {
        this.a = 28;
        Intrinsics.checkNotNullParameter(remoteFullUserMapper, "remoteFullUserMapper");
        Intrinsics.checkNotNullParameter(practiceTestsQuestionMapper, "practiceTestsQuestionMapper");
        Intrinsics.checkNotNullParameter(entitlementDataMapper, "entitlementDataMapper");
        this.b = practiceTestsQuestionMapper;
        this.c = entitlementDataMapper;
    }

    public u(androidx.compose.ui.node.E e, androidx.compose.ui.layout.K k) {
        this.a = 4;
        this.b = e;
        this.c = C0776c.z(k);
    }

    public u(com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory, com.google.firebase.messaging.p matchSettingsManagerFactory) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        Intrinsics.checkNotNullParameter(matchSettingsManagerFactory, "matchSettingsManagerFactory");
        this.b = studyModeManagerFactory;
        this.c = matchSettingsManagerFactory;
    }

    public u(Context context, com.quizlet.data.repository.widget.b bVar) {
        this.a = 2;
        this.b = (CameraManager) context.getSystemService("camera");
        this.c = bVar;
    }

    public u(View view) {
        this.a = 0;
        this.b = view;
        this.c = kotlin.l.a(kotlin.m.c, new androidx.compose.animation.core.K(this, 13));
    }

    public u(y0 delegate) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.b = delegate;
        this.c = new Object();
    }

    public u(ArrayList arrayList, ArrayList arrayList2) {
        this.a = 5;
        int size = arrayList.size();
        this.b = new int[size];
        this.c = new float[size];
        for (int i = 0; i < size; i++) {
            ((int[]) this.b)[i] = ((Integer) arrayList.get(i)).intValue();
            ((float[]) this.c)[i] = ((Float) arrayList2.get(i)).floatValue();
        }
    }

    public u(int i, int i2) {
        this.a = 5;
        this.b = new int[]{i, i2};
        this.c = new float[]{DefinitionKt.NO_Float_VALUE, 1.0f};
    }

    public u(int i, int i2, int i3) {
        this.a = 5;
        this.b = new int[]{i, i2, i3};
        this.c = new float[]{DefinitionKt.NO_Float_VALUE, 0.5f, 1.0f};
    }
}
