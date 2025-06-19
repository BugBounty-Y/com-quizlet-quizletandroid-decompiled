package com.quizlet.quizletandroid.ui.usersettings.fragments;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ ChangeProfileImageFragment b;

    public /* synthetic */ c(ChangeProfileImageFragment changeProfileImageFragment, int i) {
        this.a = i;
        this.b = changeProfileImageFragment;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        ChangeProfileImageFragment changeProfileImageFragment = this.b;
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.disposables.b it2 = (io.reactivex.rxjava3.disposables.b) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                String str = ChangeProfileImageFragment.w;
                changeProfileImageFragment.a0(true);
                break;
            default:
                List it3 = (List) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                changeProfileImageFragment.g.I("user_profile_select_picture_from_list");
                break;
        }
    }
}
