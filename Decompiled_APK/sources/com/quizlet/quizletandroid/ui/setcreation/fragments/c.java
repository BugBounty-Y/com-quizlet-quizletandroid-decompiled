package com.quizlet.quizletandroid.ui.setcreation.fragments;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ EditSetFragment b;

    public /* synthetic */ c(EditSetFragment editSetFragment, int i) {
        this.a = i;
        this.b = editSetFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        EditSetFragment editSetFragment = this.b;
        switch (this.a) {
            case 0:
                String str = EditSetFragment.J;
                editSetFragment.Y().d(editSetFragment);
                return Unit.a;
            case 1:
                String str2 = EditSetFragment.J;
                if (editSetFragment.q != null) {
                    androidx.camera.camera2.internal.compat.workaround.e.r(editSetFragment);
                    return Unit.a;
                }
                Intrinsics.m("permissionsManager");
                throw null;
            default:
                String str3 = EditSetFragment.J;
                return Boolean.valueOf(editSetFragment.requireArguments().getBoolean("isInSetFromNotesMode", false));
        }
    }
}
