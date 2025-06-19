package com.quizlet.assembly.compose.modals;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.text.H;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class t implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC0773a0 b;

    public /* synthetic */ t(InterfaceC0773a0 interfaceC0773a0, int i) {
        this.a = i;
        this.b = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                String it2 = (String) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.setValue(it2);
                break;
            case 1:
                String it3 = (String) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                this.b.setValue(it3);
                break;
            case 2:
                H result = (H) obj;
                Intrinsics.checkNotNullParameter(result, "result");
                this.b.setValue(Boolean.valueOf(result.d()));
                break;
            case 3:
                Boolean bool = (Boolean) obj;
                bool.booleanValue();
                this.b.setValue(bool);
                break;
            case 4:
                androidx.compose.ui.focus.s it4 = (androidx.compose.ui.focus.s) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                this.b.setValue(Boolean.valueOf(it4.a()));
                break;
            case 5:
                androidx.compose.ui.focus.s it5 = (androidx.compose.ui.focus.s) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                this.b.setValue(Boolean.valueOf(it5.a()));
                break;
            case 6:
                androidx.compose.ui.focus.s it6 = (androidx.compose.ui.focus.s) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                this.b.setValue(Boolean.valueOf(it6.a()));
                break;
            case 7:
                String it7 = (String) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                if (it7.length() <= 60) {
                    this.b.setValue(it7);
                }
                break;
            case 8:
                Boolean bool2 = (Boolean) obj;
                bool2.booleanValue();
                this.b.setValue(bool2);
                break;
            case 9:
                Boolean bool3 = (Boolean) obj;
                bool3.booleanValue();
                this.b.setValue(bool3);
                break;
            case 10:
                androidx.compose.ui.text.input.A it8 = (androidx.compose.ui.text.input.A) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                this.b.setValue(it8);
                break;
            case 11:
                Boolean bool4 = (Boolean) obj;
                bool4.booleanValue();
                this.b.setValue(bool4);
                break;
            case 12:
                String it9 = (String) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                this.b.setValue(it9);
                break;
            case 13:
                Boolean bool5 = (Boolean) obj;
                bool5.booleanValue();
                this.b.setValue(bool5);
                break;
            case 14:
                Boolean bool6 = (Boolean) obj;
                bool6.booleanValue();
                this.b.setValue(bool6);
                break;
            case 15:
                H it10 = (H) obj;
                Intrinsics.checkNotNullParameter(it10, "it");
                this.b.setValue(Boolean.valueOf(it10.d()));
                break;
            case 16:
                String it11 = (String) obj;
                Intrinsics.checkNotNullParameter(it11, "it");
                this.b.setValue(it11);
                break;
            case 17:
                String newValue = (String) obj;
                Intrinsics.checkNotNullParameter(newValue, "newValue");
                this.b.setValue(newValue);
                break;
            case 18:
                String it12 = (String) obj;
                Intrinsics.checkNotNullParameter(it12, "it");
                this.b.setValue(it12);
                break;
            case 19:
                String it13 = (String) obj;
                Intrinsics.checkNotNullParameter(it13, "it");
                this.b.setValue(it13);
                break;
            case 20:
                String it14 = (String) obj;
                Intrinsics.checkNotNullParameter(it14, "it");
                this.b.setValue(it14);
                break;
            case 21:
                androidx.compose.ui.layout.r it15 = (androidx.compose.ui.layout.r) obj;
                Intrinsics.checkNotNullParameter(it15, "it");
                this.b.setValue(new androidx.compose.ui.geometry.e(R5.f(it15.t())));
                break;
            case EventType.WINDOW_STATE /* 22 */:
                androidx.compose.ui.focus.s it16 = (androidx.compose.ui.focus.s) obj;
                Intrinsics.checkNotNullParameter(it16, "it");
                this.b.setValue(Boolean.valueOf(it16.a()));
                break;
            case EventType.AUDIO /* 23 */:
                androidx.compose.ui.focus.s it17 = (androidx.compose.ui.focus.s) obj;
                Intrinsics.checkNotNullParameter(it17, "it");
                this.b.setValue(Boolean.valueOf(it17.a()));
                break;
            case EventType.VIDEO /* 24 */:
                String it18 = (String) obj;
                Intrinsics.checkNotNullParameter(it18, "it");
                this.b.setValue(it18);
                break;
            case EventType.SUBS /* 25 */:
                String it19 = (String) obj;
                Intrinsics.checkNotNullParameter(it19, "it");
                this.b.setValue(it19);
                break;
            case EventType.CDN /* 26 */:
                String it20 = (String) obj;
                Intrinsics.checkNotNullParameter(it20, "it");
                this.b.setValue(it20);
                break;
            case 27:
                String it21 = (String) obj;
                Intrinsics.checkNotNullParameter(it21, "it");
                this.b.setValue(it21);
                break;
            case 28:
                String it22 = (String) obj;
                Intrinsics.checkNotNullParameter(it22, "it");
                this.b.setValue(it22);
                break;
            default:
                String it23 = (String) obj;
                Intrinsics.checkNotNullParameter(it23, "it");
                this.b.setValue(it23);
                break;
        }
        return Unit.a;
    }
}
