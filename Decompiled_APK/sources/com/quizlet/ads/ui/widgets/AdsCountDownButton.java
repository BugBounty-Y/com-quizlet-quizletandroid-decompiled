package com.quizlet.ads.ui.widgets;

import android.content.Context;
import android.os.CountDownTimer;
import android.util.AttributeSet;
import android.widget.TextView;
import androidx.navigation.U;
import com.braze.requests.framework.o;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.v;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AdsCountDownButton extends com.quizlet.assembly.widgets.buttons.d implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public static final /* synthetic */ int B = 0;
    public f A;
    public dagger.hilt.android.internal.managers.f x;
    public boolean y;
    public d z;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AdsCountDownButton(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final void setUpCountDown(b bVar) {
        Context context = getContext();
        bVar.getClass();
        String string = context.getString(R.string.learn_ads_button_count_down, 5L);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        setText(string);
        f fVar = this.A;
        if (fVar != null) {
            U onTick = new U(14, this, bVar);
            o onFinish = new o(this, bVar);
            com.google.firebase.crashlytics.internal.settings.b bVar2 = (com.google.firebase.crashlytics.internal.settings.b) fVar;
            Intrinsics.checkNotNullParameter(onTick, "onTick");
            Intrinsics.checkNotNullParameter(onFinish, "onFinish");
            CountDownTimer countDownTimer = (CountDownTimer) bVar2.b;
            if (countDownTimer != null) {
                countDownTimer.cancel();
            }
            bVar2.b = new g(5000L, onTick, onFinish).start();
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.x == null) {
            this.x = new dagger.hilt.android.internal.managers.f(this);
        }
        return this.x.d();
    }

    public final f getAdsCountDownTimer() {
        return this.A;
    }

    @NotNull
    public final d getState() {
        return this.z;
    }

    public final void r() {
        int i;
        int i2;
        d dVar = this.z;
        boolean z = dVar instanceof c;
        a aVar = a.a;
        if (z) {
            i = R.drawable.primary_button_background;
        } else {
            if (!(dVar instanceof b) && !Intrinsics.b(dVar, aVar)) {
                throw new NoWhenBranchMatchedException();
            }
            i = R.drawable.bordered_text_button_selection_background;
        }
        setBackgroundResource(i);
        TextView textView = getBinding().d;
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        d dVar2 = this.z;
        if (dVar2 instanceof c) {
            i2 = R.attr.AssemblyPrimaryButtonText;
        } else {
            if (!(dVar2 instanceof b) && !Intrinsics.b(dVar2, aVar)) {
                throw new NoWhenBranchMatchedException();
            }
            i2 = R.attr.AssemblySecondaryButtonText;
        }
        textView.setTextColor(com.quizlet.themes.extensions.a.a(context, i2));
        setEnabled(this.z instanceof c);
        d dVar3 = this.z;
        if (Intrinsics.b(dVar3, aVar)) {
            return;
        }
        if (dVar3 instanceof b) {
            setUpCountDown((b) dVar3);
            return;
        }
        if (!(dVar3 instanceof c)) {
            throw new NoWhenBranchMatchedException();
        }
        Context context2 = getContext();
        ((c) dVar3).getClass();
        String string = context2.getString(R.string.learn_ads_button_enabled);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        setText(string);
    }

    public final void setAdsCountDownTimer(f fVar) {
        this.A = fVar;
    }

    public final void setState(@NotNull d value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.z = value;
        r();
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.y;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AdsCountDownButton(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public AdsCountDownButton(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet);
        if (!isInEditMode()) {
            if (this.x == null) {
                this.x = new dagger.hilt.android.internal.managers.f(this);
            }
            dagger.hilt.internal.b bVarC = this.x.c(true);
            if (bVarC != null && ((!(bVarC instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) bVarC).u()) && !this.y)) {
                this.y = true;
                ((v) ((e) d())).getClass();
                setAdsCountDownTimer(new com.google.firebase.crashlytics.internal.settings.b());
            }
        }
        this.z = a.a;
        r();
    }
}
