package com.quizlet.quizletandroid.ui.group;

import android.content.Context;
import androidx.fragment.app.I;
import com.google.android.gms.internal.mlkit_vision_barcode.I6;
import com.quizlet.api.error.ModelErrorException;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ModelError;
import com.quizlet.api.util.ApiErrorResolver;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTabLayout;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.H;
import com.quizlet.uicommon.ui.common.dialogs.k;
import java.io.IOException;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlin.v;

/* loaded from: classes3.dex */
public final class g implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ GroupFragment b;

    public /* synthetic */ g(GroupFragment groupFragment, int i) {
        this.a = i;
        this.b = groupFragment;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) throws Exception {
        GroupFragment groupFragment = this.b;
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.disposables.b disposable = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(disposable, "disposable");
                String str = GroupFragment.M;
                ((k) groupFragment.E.getValue()).show();
                return;
            case 1:
                ApiResponse p0 = (ApiResponse) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                String str2 = GroupFragment.M;
                List<DBGroupMembership> groupMemberships = p0.getModelWrapper().getGroupMemberships();
                com.quizlet.infra.legacysyncengine.managers.h hVar = groupFragment.m;
                if (hVar == null) {
                    Intrinsics.m("saveManager");
                    throw null;
                }
                hVar.a(groupMemberships, null);
                groupFragment.X();
                return;
            case 2:
                Throwable p02 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                String str3 = GroupFragment.M;
                if (!(p02 instanceof ModelErrorException)) {
                    if (!(p02 instanceof IOException)) {
                        timber.log.c.a.e(p02);
                        return;
                    }
                    String string = groupFragment.getString(R.string.unable_to_reach_quizlet_msg);
                    Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                    com.google.android.material.snackbar.h hVarE = I6.e(((H) groupFragment.J()).c, string);
                    hVarE.k = 0;
                    hVarE.i();
                    return;
                }
                timber.log.c.a.p(p02);
                ModelError error = ((ModelErrorException) p02).getError();
                Context context = groupFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                String identifier = error.getIdentifier();
                Intrinsics.checkNotNullParameter(context, "context");
                Integer numB = ApiErrorResolver.b(identifier);
                String string2 = numB != null ? context.getString(numB.intValue()) : null;
                if (string2 != null) {
                    com.google.android.material.snackbar.h hVarE2 = I6.e(((H) groupFragment.J()).c, string2);
                    hVarE2.k = 0;
                    hVarE2.i();
                    return;
                }
                return;
            case 3:
                DBGroup p03 = (DBGroup) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                groupFragment.F = p03;
                groupFragment.requireActivity().invalidateOptionsMenu();
                groupFragment.requireActivity().setTitle(R.string.class_title);
                groupFragment.T(groupFragment.F);
                return;
            case 4:
                DBGroupMembership membership = (DBGroupMembership) obj;
                Intrinsics.checkNotNullParameter(membership, "membership");
                groupFragment.H = membership;
                groupFragment.requireActivity().invalidateOptionsMenu();
                return;
            case 5:
                e userClassData = (e) obj;
                Intrinsics.checkNotNullParameter(userClassData, "userClassData");
                String str4 = GroupFragment.M;
                if (userClassData.a) {
                    groupFragment.X();
                    return;
                }
                ((QTabLayout) ((H) groupFragment.J()).b.d).setVisibility(8);
                ((H) groupFragment.J()).d.setSwipeable(false);
                QButton qButton = (QButton) groupFragment.W().g;
                qButton.setVisibility(0);
                UserInfoCache userInfoCache = groupFragment.s;
                if (userInfoCache == null) {
                    Intrinsics.m("userInfoCache");
                    throw null;
                }
                qButton.setEnabled(userInfoCache.b());
                qButton.setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(groupFragment, 4));
                return;
            default:
                v vVar = (v) obj;
                Intrinsics.checkNotNullParameter(vVar, "<destruct>");
                Object obj2 = vVar.a;
                Intrinsics.checkNotNullExpressionValue(obj2, "component1(...)");
                Object obj3 = vVar.b;
                Intrinsics.checkNotNullExpressionValue(obj3, "component2(...)");
                Object obj4 = vVar.c;
                Intrinsics.checkNotNullExpressionValue(obj4, "component3(...)");
                groupFragment.I = ((Boolean) obj2).booleanValue();
                groupFragment.J = ((Boolean) obj3).booleanValue();
                groupFragment.K = ((Boolean) obj4).booleanValue();
                I activity = groupFragment.getActivity();
                if (activity != null) {
                    activity.invalidateOptionsMenu();
                    return;
                }
                return;
        }
    }
}
