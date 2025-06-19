package com.quizlet.infra.legacysyncengine.models.serializers;

import android.view.View;
import androidx.core.util.c;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import com.comscore.streaming.EventType;
import com.quizlet.api.HttpStatusRangeConstants;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ModelError;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBImageRef;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.orm.Relationship;
import com.quizlet.quizletandroid.ui.common.adapter.f;
import com.quizlet.quizletandroid.ui.common.adapter.g;
import com.quizlet.quizletandroid.ui.common.adapter.presenter.d;
import com.quizlet.quizletandroid.ui.diagramming.DiagramOverviewActivity;
import com.quizlet.quizletandroid.ui.group.GroupFragment;
import com.quizlet.quizletandroid.ui.group.classcontent.ClassContentListFragment;
import com.quizlet.quizletandroid.ui.live.QuizletLiveActivity;
import com.quizlet.quizletandroid.ui.profile.ProfileActivity;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import com.quizlet.studiablemodels.diagrams.DiagramDataKt;
import com.quizlet.uicommon.ui.common.dialogs.e;
import io.reactivex.rxjava3.functions.b;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import io.reactivex.rxjava3.internal.operators.observable.U;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import org.prebid.mobile.api.data.InitializationStatus;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements b, h, i, f, g, d, io.reactivex.rxjava3.functions.f, InterfaceC1062t, com.quizlet.uicommon.ui.common.dialogs.f {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.f
    public Object a(Object obj, Object obj2, Object obj3, Object obj4) {
        List list = (List) obj2;
        List list2 = (List) obj4;
        int i = DiagramOverviewActivity.o1;
        DiagramData.Builder builder = new DiagramData.Builder();
        builder.d(((DBStudySet) obj3).getId());
        DBImage image = ((DBImageRef) obj).getImage();
        Intrinsics.checkNotNullExpressionValue(image, "getImage(...)");
        builder.c(image);
        Intrinsics.d(list);
        Intrinsics.d(list2);
        Intrinsics.checkNotNullParameter(list2, "<this>");
        ArrayList arrayList = new ArrayList(C.q(list2, 10));
        Iterator it2 = list2.iterator();
        while (it2.hasNext()) {
            arrayList.add(((Pair) it2.next()).a);
        }
        builder.b(DiagramDataKt.a(list, arrayList));
        return builder.a();
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                return ApiThreeRequestSerializer.lambda$requestFilesForModels$0((ArrayList) obj, (List) obj2);
            default:
                return new c((ApiResponse) obj, (Integer) obj2);
        }
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.g
    public void b() {
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.f
    public void c(e eVar, int i) {
        switch (this.a) {
            case EventType.WINDOW_STATE /* 22 */:
                int i2 = QuizletLiveActivity.z;
                eVar.dismiss();
                break;
            case EventType.AUDIO /* 23 */:
            case EventType.VIDEO /* 24 */:
            case EventType.SUBS /* 25 */:
            default:
                eVar.dismiss();
                break;
            case EventType.CDN /* 26 */:
                eVar.dismiss();
                break;
            case 27:
                eVar.dismiss();
                break;
            case 28:
                eVar.dismiss();
                break;
        }
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.f
    public void d(DiagramData diagramData) {
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.presenter.d
    public void e(DBTerm dBTerm) {
        int i = DiagramOverviewActivity.o1;
    }

    public void f(InitializationStatus status) {
        Intrinsics.checkNotNullParameter(status, "status");
        int iOrdinal = status.ordinal();
        if (iOrdinal == 0) {
            timber.log.c.a.g("Prebid SDK successfully initialized", new Object[0]);
            return;
        }
        if (iOrdinal == 1) {
            timber.log.c.a.o("Prebid SDK Prebid Server status checking failed: " + status + "\\n" + status.a, new Object[0]);
            return;
        }
        if (iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        timber.log.c.a.d("Prebid SDK initialization error: " + status + "\n" + status.a, new Object[0]);
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        switch (this.a) {
            case 2:
                return com.quizlet.infra.legacysyncengine.net.f.i.contains(((Relationship) obj).getFromModelType());
            case 3:
                return ((List) obj).size() > 0;
            case 4:
            default:
                return ((Boolean) obj).booleanValue();
            case 5:
                return ((U) obj).a != com.quizlet.infra.legacysyncengine.net.constants.a.a;
            case 6:
                return !((List) obj).isEmpty();
            case 7:
                return !((List) obj).isEmpty();
            case 8:
                com.quizlet.infra.legacysyncengine.tasks.parse.e eVar = (com.quizlet.infra.legacysyncengine.tasks.parse.e) obj;
                return (eVar.c == null && eVar.e == null && eVar.d == null) ? false : true;
            case 9:
                return ((com.quizlet.infra.legacysyncengine.tasks.parse.e) obj).d != null;
            case 10:
                ModelError modelError = ((com.quizlet.infra.legacysyncengine.tasks.parse.e) obj).d;
                return modelError != null && HttpStatusRangeConstants.b.a(modelError.getCode());
            case 11:
                return ((com.quizlet.infra.legacysyncengine.tasks.parse.e) obj).e != null;
        }
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) {
        switch (this.a) {
            case 19:
                String str = GroupFragment.M;
                androidx.core.graphics.e eVarG = d0.a.g(647);
                Intrinsics.d(view);
                view.setPadding(eVarG.a, eVarG.b, eVarG.c, view.getPaddingBottom());
                return d0;
            case 20:
                String str2 = ClassContentListFragment.n;
                androidx.core.graphics.e eVarG2 = d0.a.g(519);
                Intrinsics.d(view);
                view.setPadding(view.getPaddingLeft(), view.getPaddingTop(), view.getPaddingRight(), eVarG2.d);
                return D0.b;
            case 21:
                view.setPadding(view.getPaddingStart(), view.getPaddingTop(), view.getPaddingEnd(), d0.a.g(519).d);
                return D0.b;
            default:
                com.quizlet.quizletandroid.ui.profile.b bVar = ProfileActivity.p;
                androidx.core.graphics.e eVarG3 = d0.a.g(647);
                Intrinsics.d(view);
                view.setPadding(view.getPaddingLeft(), eVarG3.b, view.getPaddingRight(), view.getPaddingBottom());
                return d0;
        }
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 1:
                return (io.reactivex.rxjava3.core.i) obj;
            case 4:
                return new com.quizlet.infra.legacysyncengine.net.request.c((List) obj);
            case 13:
                Throwable it2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                timber.log.c.a.e(it2);
                return Boolean.FALSE;
            default:
                return Boolean.valueOf(!((Boolean) obj).booleanValue());
        }
    }
}
