package com.quizlet.quizletandroid.ui.setcreation.imageupload;

import android.view.View;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import androidx.core.view.z0;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.util.ApiThreeWrapperUtil;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import com.quizlet.infra.legacysyncengine.net.request.c;
import com.quizlet.quizletandroid.ui.studymodes.testmode.activities.TestStudyModeActivity;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeCheckPointView;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeResultsView;
import com.quizlet.quizletandroid.ui.usersettings.activities.ChangeProfileImageActivity;
import com.quizlet.quizletandroid.ui.usersettings.fragments.ChangeProfileImageFragment;
import com.quizlet.quizletandroid.util.l;
import com.quizlet.quizletandroid.util.n;
import com.quizlet.qutils.rx.b;
import com.quizlet.uicommon.ui.common.dialogs.ImageOverlayDialogFragment;
import com.quizlet.uicommon.ui.common.dialogs.f;
import io.reactivex.rxjava3.functions.e;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import retrofit2.K;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements e, h, i, f, InterfaceC1062t, com.quizlet.quizletandroid.ui.common.adapter.e, io.reactivex.rxjava3.functions.f, b {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.f
    public Object a(Object obj, Object obj2, Object obj3, Object obj4) {
        long jLongValue = ((Long) obj).longValue();
        long jLongValue2 = ((Long) obj2).longValue();
        long jLongValue3 = ((Long) obj3).longValue();
        long jLongValue4 = ((Long) obj4).longValue();
        int i = jLongValue > 0 ? (int) (jLongValue / 1000) : -1;
        long j = 1000;
        int i2 = (int) (jLongValue3 / j);
        int i3 = (int) (jLongValue2 / j);
        int i4 = (int) (jLongValue4 / j);
        if (i > 0) {
            i = ((i - i2) - i3) - i4;
        }
        return new l(i2, i3, i4, i);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 1:
                break;
            case 12:
                K k = (K) obj;
                ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) k.b;
                if (apiThreeWrapper != null) {
                    break;
                } else {
                    break;
                }
        }
        return ApiThreeWrapperUtil.a((ApiThreeWrapper) obj);
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.f
    public void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i) {
        String str = TestStudyModeActivity.v;
        eVar.dismiss();
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.e
    public void e(String str) {
        switch (this.a) {
            case 5:
                int i = WriteModeCheckPointView.n;
                break;
            default:
                int i2 = WriteModeResultsView.q;
                break;
        }
    }

    @Override // io.reactivex.rxjava3.functions.e
    public Object k(Object obj, Object obj2, Object obj3) {
        Boolean canUploadImages = (Boolean) obj2;
        Boolean canUpsell = (Boolean) obj3;
        Intrinsics.checkNotNullParameter((LoggedInUserStatus) obj, "<unused var>");
        Intrinsics.checkNotNullParameter(canUploadImages, "canUploadImages");
        Intrinsics.checkNotNullParameter(canUpsell, "canUpsell");
        return Boolean.valueOf(canUploadImages.booleanValue() || canUpsell.booleanValue());
    }

    @Override // com.quizlet.qutils.rx.b
    public void run() {
        String str = ImageOverlayDialogFragment.x;
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        com.quizlet.infra.legacysyncengine.net.request.i iVarA = ((c) obj).a();
        Map map = iVarA.b;
        if (map != null && map.size() > 0) {
            return true;
        }
        Map map2 = iVarA.c;
        return map2 != null && map2.size() > 0;
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 windowInsets, View rootView) {
        switch (this.a) {
            case 4:
                z0 z0Var = windowInsets.a;
                androidx.core.graphics.e eVarG = z0Var.g(647);
                androidx.core.graphics.e eVarG2 = z0Var.g(8);
                rootView.setPadding(eVarG.a, eVarG.b, eVarG.c, eVarG.d + eVarG2.d);
                break;
            case 17:
                int i = ChangeProfileImageActivity.q;
                androidx.core.graphics.e eVarG3 = windowInsets.a.g(647);
                rootView.setPadding(eVarG3.a, eVarG3.b, eVarG3.c, 0);
                break;
            case 18:
                String str = ChangeProfileImageFragment.w;
                androidx.core.graphics.e eVarG4 = windowInsets.a.g(647);
                Intrinsics.d(rootView);
                rootView.setPadding(eVarG4.a, rootView.getPaddingTop(), eVarG4.c, eVarG4.d);
                break;
            default:
                Intrinsics.checkNotNullParameter(rootView, "rootView");
                Intrinsics.checkNotNullParameter(windowInsets, "windowInsets");
                androidx.core.graphics.e eVarG5 = windowInsets.a.g(647);
                Intrinsics.checkNotNullExpressionValue(eVarG5, "getInsets(...)");
                rootView.setPadding(eVarG5.a, eVarG5.b, eVarG5.c, eVarG5.d);
                break;
        }
        return D0.b;
    }

    public /* synthetic */ a(n nVar) {
        this.a = 19;
    }
}
