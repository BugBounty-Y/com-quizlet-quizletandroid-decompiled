package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.navigation;

import androidx.navigation.H;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4942a;

/* loaded from: classes3.dex */
public final /* synthetic */ class a extends C4942a implements Function0 {
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.h = i3;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.h) {
            case 0:
                ((H) this.a).e();
                break;
            case 1:
                x.d((x) this.a);
                break;
            default:
                x.d((x) this.a);
                break;
        }
        return Unit.a;
    }
}
