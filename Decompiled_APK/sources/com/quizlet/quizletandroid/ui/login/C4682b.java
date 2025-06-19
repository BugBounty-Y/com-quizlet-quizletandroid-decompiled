package com.quizlet.quizletandroid.ui.login;

import android.content.res.Resources;
import android.os.Bundle;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.views.DatePickerDialogFragment;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.quizletandroid.ui.login.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4682b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ BaseSignupFragment j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4682b(BaseSignupFragment baseSignupFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = baseSignupFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4682b(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4682b) create((Unit) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Resources.NotFoundException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        BaseSignupFragment baseSignupFragment = this.j;
        if (baseSignupFragment.isAdded() && baseSignupFragment.getParentFragmentManager().E("DatePickerDialogFragment") == null) {
            int year = baseSignupFragment.Q().getYear();
            int i = baseSignupFragment.Q().getMonth().a;
            int day = baseSignupFragment.Q().getDay();
            String string = baseSignupFragment.getResources().getString(R.string.birthdate_input_dialog_title);
            DatePickerDialogFragment datePickerDialogFragment = new DatePickerDialogFragment();
            Bundle bundle = new Bundle();
            bundle.putInt("Year", year);
            bundle.putInt("Month", i);
            bundle.putInt("Day", day);
            bundle.putString("Message", string);
            bundle.putInt("Range", 2);
            datePickerDialogFragment.setArguments(bundle);
            datePickerDialogFragment.s = baseSignupFragment.Q();
            datePickerDialogFragment.q = baseSignupFragment.Q();
            datePickerDialogFragment.O(baseSignupFragment.getParentFragmentManager(), "DatePickerDialogFragment");
        }
        return Unit.a;
    }
}
