package com.quizlet.features.practicetest.detail.composables;

import androidx.compose.runtime.InterfaceC0773a0;
import com.comscore.streaming.EventType;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC0773a0 b;

    public /* synthetic */ f(InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                break;
            case 1:
                this.b.setValue(Boolean.FALSE);
                break;
            case 2:
                this.b.setValue(Boolean.FALSE);
                break;
            case 3:
                this.b.setValue(null);
                break;
            case 4:
                this.b.setValue(null);
                break;
            case 5:
                Boolean bool = (Boolean) this.b.getValue();
                bool.getClass();
                break;
            case 6:
                break;
            case 7:
                Boolean bool2 = (Boolean) this.b.getValue();
                bool2.getClass();
                break;
            case 8:
                Boolean bool3 = (Boolean) this.b.getValue();
                bool3.getClass();
                break;
            case 9:
                Boolean bool4 = (Boolean) this.b.getValue();
                bool4.getClass();
                break;
            case 10:
                this.b.setValue(Boolean.FALSE);
                break;
            case 11:
                this.b.setValue(Boolean.FALSE);
                break;
            case 12:
                this.b.setValue(Boolean.FALSE);
                break;
            case 13:
                this.b.setValue(Boolean.FALSE);
                break;
            case 14:
                this.b.setValue(Boolean.FALSE);
                break;
            case 15:
                this.b.setValue(Boolean.TRUE);
                break;
            case 16:
                this.b.setValue(Boolean.FALSE);
                break;
            case 17:
                this.b.setValue(Boolean.FALSE);
                break;
            case 18:
                this.b.setValue("");
                break;
            case 19:
                this.b.setValue("");
                break;
            case 20:
                this.b.setValue("");
                break;
            case 21:
                this.b.setValue("");
                break;
            case EventType.WINDOW_STATE /* 22 */:
                this.b.setValue("");
                break;
            case EventType.AUDIO /* 23 */:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                break;
            case EventType.VIDEO /* 24 */:
                this.b.setValue(Boolean.valueOf(!((Boolean) r0.getValue()).booleanValue()));
                break;
            default:
                this.b.setValue(Boolean.FALSE);
                break;
        }
        return Unit.a;
    }
}
