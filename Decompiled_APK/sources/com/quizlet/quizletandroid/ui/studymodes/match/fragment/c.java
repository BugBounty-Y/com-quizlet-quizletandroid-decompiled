package com.quizlet.quizletandroid.ui.studymodes.match.fragment;

import android.view.MotionEvent;
import android.view.View;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.features.match.data.C4345a;
import com.quizlet.features.match.data.C4346b;
import com.quizlet.features.match.data.C4347c;
import com.quizlet.features.match.data.C4358n;
import com.quizlet.features.match.data.b0;
import com.quizlet.features.match.data.c0;
import com.quizlet.quizletandroid.ui.studymodes.match.view.MatchCardView;
import kotlin.NoWhenBranchMatchedException;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements View.OnTouchListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ BaseFragment c;

    public /* synthetic */ c(BaseFragment baseFragment, int i, int i2) {
        this.a = i2;
        this.c = baseFragment;
        this.b = i;
    }

    @Override // android.view.View.OnTouchListener
    public final boolean onTouch(View view, MotionEvent motionEvent) {
        int i = this.b;
        BaseFragment baseFragment = this.c;
        switch (this.a) {
            case 0:
                String str = DiagramMatchGameFragment.t;
                if (motionEvent.getAction() != 0 || !(view instanceof MatchCardView)) {
                    return false;
                }
                com.quizlet.features.match.viewmodel.d dVarW = ((DiagramMatchGameFragment) baseFragment).W();
                C4345a c4345a = (C4345a) ((C4346b) dVarW.C()).c.get(i);
                if (c4345a.a instanceof C4358n) {
                    c4345a.b(!c4345a.a());
                    int iOrdinal = com.quizlet.features.match.viewmodel.c.E(c4345a, dVarW.k, Integer.valueOf(i)).ordinal();
                    if (iOrdinal == 0) {
                        dVarW.k = Integer.valueOf(i);
                    } else if (iOrdinal == 1) {
                        dVarW.k = null;
                    } else if (iOrdinal == 2) {
                        Integer num = dVarW.k;
                        if (num == null) {
                            throw new IllegalArgumentException("Required value was null.");
                        }
                        ((C4345a) ((C4346b) dVarW.C()).c.get(num.intValue())).b(false);
                        dVarW.k = Integer.valueOf(i);
                    } else if (iOrdinal != 3) {
                        throw new NoWhenBranchMatchedException();
                    }
                    Long l = dVarW.l;
                    Integer num2 = dVarW.k;
                    if (l != null && num2 != null) {
                        dVarW.B(new C4347c(num2.intValue(), l.longValue()));
                    }
                    dVarW.I();
                }
                return true;
            default:
                String str2 = StandardMatchGameFragment.r;
                if (motionEvent.getAction() != 0 || !(view instanceof MatchCardView)) {
                    return false;
                }
                com.quizlet.features.match.viewmodel.i iVarU = ((StandardMatchGameFragment) baseFragment).U();
                C4345a c4345a2 = (C4345a) ((b0) iVarU.C()).a.get(i);
                if (c4345a2.a instanceof C4358n) {
                    c4345a2.b(!c4345a2.a());
                    int iOrdinal2 = com.quizlet.features.match.viewmodel.c.E(c4345a2, iVarU.k, Integer.valueOf(i)).ordinal();
                    if (iOrdinal2 == 0) {
                        iVarU.k = Integer.valueOf(i);
                    } else if (iOrdinal2 == 1) {
                        iVarU.k = null;
                    } else if (iOrdinal2 == 2) {
                        Integer num3 = iVarU.k;
                        if (num3 == null) {
                            throw new IllegalArgumentException("Required value was null.");
                        }
                        iVarU.B(new c0(num3.intValue(), i));
                    } else if (iOrdinal2 != 3) {
                        throw new NoWhenBranchMatchedException();
                    }
                    iVarU.I();
                }
                return true;
        }
    }
}
