package com.quizlet.quizletandroid.ui.subject;

import android.content.Context;
import androidx.appcompat.app.y;
import androidx.compose.animation.core.C0238e;
import androidx.compose.foundation.pager.C0466e;
import androidx.compose.runtime.H;
import androidx.compose.ui.platform.ComposeView;
import androidx.glance.appwidget.lazy.h;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.quizlet.features.folders.composables.V;
import com.quizlet.qutils.string.g;
import com.quizlet.search.composables.t;
import com.quizlet.uicommon.ui.common.widgets.QSegmentedControl;
import com.quizlet.uicommon.ui.common.widgets.i;
import com.skydoves.balloon.compose.BalloonComposeView;
import com.skydoves.balloon.compose.BalloonKt;
import io.ktor.http.l;
import io.ktor.http.m;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ f(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                Integer num = (Integer) obj;
                if (num.intValue() == ((Number) ((C0466e) this.b).t.getValue()).intValue()) {
                    ((Function1) this.c).invoke(num);
                }
                return Unit.a;
            case 1:
                h LazyColumn = (h) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                kotlinx.collections.immutable.b bVar = (kotlinx.collections.immutable.b) this.b;
                LazyColumn.b(bVar.size(), new com.quizlet.assembly.compose.menu.e(bVar, 23), new androidx.compose.runtime.internal.d(true, -1405343893, new V(bVar, bVar, (androidx.appcompat.view.a) this.c)));
                return Unit.a;
            case 2:
                com.quizlet.search.data.a it2 = (com.quizlet.search.data.a) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                E.A((C) this.c, null, null, new t((C0466e) this.b, it2, null), 3);
                return Unit.a;
            case 3:
                String query = (String) obj;
                Intrinsics.checkNotNullParameter(query, "query");
                androidx.compose.ui.focus.h.a((androidx.compose.ui.focus.h) this.b);
                ((Function1) this.c).invoke(query);
                return Unit.a;
            case 4:
                androidx.compose.ui.unit.b offset = (androidx.compose.ui.unit.b) obj;
                Intrinsics.checkNotNullParameter(offset, "$this$offset");
                return new androidx.compose.ui.unit.h(P5.b((int) ((Number) ((C0238e) this.b).d()).floatValue(), (int) ((Number) ((C0238e) this.c).d()).floatValue()));
            case 5:
                QSegmentedControl it3 = (QSegmentedControl) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                Intrinsics.checkNotNullParameter(it3, "<this>");
                y state = (y) this.b;
                Intrinsics.checkNotNullParameter(state, "state");
                g gVarM = state.m(0);
                Context context = it3.getContext();
                Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
                it3.setLeftButtonText(gVarM.a(context));
                g gVarG = state.g(1);
                Context context2 = it3.getContext();
                Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
                it3.setLeftButtonContentDescription(gVarG.a(context2));
                List list = (List) state.b;
                if (list.size() == 3) {
                    g gVarM2 = state.m(1);
                    Context context3 = it3.getContext();
                    Intrinsics.checkNotNullExpressionValue(context3, "getContext(...)");
                    it3.setMiddleButtonText(gVarM2.a(context3));
                    g gVarG2 = state.g(1);
                    Context context4 = it3.getContext();
                    Intrinsics.checkNotNullExpressionValue(context4, "getContext(...)");
                    it3.setMiddleButtonContentDescription(gVarG2.a(context4));
                    g gVarM3 = state.m(2);
                    Context context5 = it3.getContext();
                    Intrinsics.checkNotNullExpressionValue(context5, "getContext(...)");
                    it3.setRightButtonText(gVarM3.a(context5));
                    g gVarG3 = state.g(2);
                    Context context6 = it3.getContext();
                    Intrinsics.checkNotNullExpressionValue(context6, "getContext(...)");
                    it3.setRightButtonContentDescription(gVarG3.a(context6));
                } else {
                    g gVarM4 = state.m(1);
                    Context context7 = it3.getContext();
                    Intrinsics.checkNotNullExpressionValue(context7, "getContext(...)");
                    it3.setRightButtonText(gVarM4.a(context7));
                    g gVarG4 = state.g(1);
                    Context context8 = it3.getContext();
                    Intrinsics.checkNotNullExpressionValue(context8, "getContext(...)");
                    it3.setRightButtonContentDescription(gVarG4.a(context8));
                    it3.setMiddleButtonText(null);
                }
                Object obj2 = state.c;
                int iIndexOf = list.indexOf(obj2);
                if (iIndexOf != -1) {
                    it3.setCheckedSegment((list.size() != 3 && iIndexOf == 1) ? i.c : i.values()[iIndexOf]);
                    it3.setOnCheckedChangedListener(new com.quizlet.remote.model.user.a(state, (Function1) this.c));
                    return Unit.a;
                }
                throw new IllegalArgumentException(("Item " + obj2 + " not present: " + list).toString());
            case 6:
                com.quizlet.viewmodel.state.c cVar = (com.quizlet.viewmodel.state.c) obj;
                if (Intrinsics.b(cVar, com.quizlet.viewmodel.state.a.a)) {
                    ((Function0) this.b).invoke();
                } else {
                    if (!(cVar instanceof com.quizlet.viewmodel.state.b)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    ((Function1) this.c).invoke(((com.quizlet.viewmodel.state.b) cVar).a);
                }
                return Unit.a;
            case 7:
                return BalloonKt.Balloon$lambda$31$lambda$30((BalloonComposeView) this.b, (ComposeView) this.c, (H) obj);
            case 8:
                io.ktor.client.engine.okhttp.b bVar2 = (io.ktor.client.engine.okhttp.b) obj;
                Intrinsics.checkNotNullParameter(bVar2, "<this>");
                ((Function1) this.c).invoke(bVar2);
                ((com.perimeterx.mobile_sdk.api_data.g) this.b).invoke(bVar2);
                return Unit.a;
            case 9:
                l buildHeaders = (l) obj;
                Intrinsics.checkNotNullParameter(buildHeaders, "$this$buildHeaders");
                m stringValues = (m) this.b;
                buildHeaders.getClass();
                Intrinsics.checkNotNullParameter(stringValues, "stringValues");
                stringValues.b(new com.quizlet.features.settings.composables.dialogs.a(buildHeaders, 23));
                ((io.ktor.http.content.c) this.c).c();
                io.ktor.http.e stringValues2 = io.ktor.http.e.c;
                Intrinsics.checkNotNullParameter(stringValues2, "stringValues");
                stringValues2.b(new com.quizlet.features.settings.composables.dialogs.a(buildHeaders, 23));
                return Unit.a;
            case 10:
                ((kotlinx.coroutines.android.d) this.b).b.removeCallbacks((com.skydoves.balloon.compose.a) this.c);
                return Unit.a;
            default:
                ((kotlinx.coroutines.sync.b) this.c).getClass();
                ((kotlinx.coroutines.sync.c) this.b).f(null);
                return Unit.a;
        }
    }

    public /* synthetic */ f(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }
}
