package com.quizlet.features.flashcards.settings.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.focus.s;
import com.quizlet.features.notes.common.events.z;
import com.quizlet.features.universaluploadflow.data.m;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class e implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ InterfaceC0773a0 c;

    public /* synthetic */ e(int i, InterfaceC0773a0 interfaceC0773a0, Function1 function1) {
        this.a = i;
        this.b = function1;
        this.c = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                Boolean bool = (Boolean) obj;
                bool.booleanValue();
                this.c.setValue(bool);
                this.b.invoke(bool);
                break;
            case 1:
                Boolean bool2 = (Boolean) obj;
                bool2.booleanValue();
                this.c.setValue(bool2);
                this.b.invoke(bool2);
                break;
            case 2:
                String it2 = (String) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.c.setValue(it2);
                this.b.invoke(it2);
                break;
            case 3:
                String it3 = (String) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                this.c.setValue(it3);
                this.b.invoke(it3);
                break;
            case 4:
                String it4 = (String) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                this.c.setValue(it4);
                this.b.invoke(it4);
                break;
            case 5:
                String it5 = (String) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                this.c.setValue(it5);
                this.b.invoke(new com.quizlet.features.infra.folder.tag.screenstates.h(it5));
                break;
            case 6:
                String it6 = (String) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                this.b.invoke(new z(it6));
                this.c.setValue(it6);
                break;
            case 7:
                Boolean bool3 = (Boolean) obj;
                bool3.booleanValue();
                this.c.setValue(bool3);
                this.b.invoke(bool3);
                break;
            case 8:
                String it7 = (String) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                this.c.setValue(it7);
                this.b.invoke(it7);
                break;
            case 9:
                Boolean bool4 = (Boolean) obj;
                boolean zBooleanValue = bool4.booleanValue();
                this.c.setValue(bool4);
                this.b.invoke(new m(zBooleanValue));
                break;
            case 10:
                String it8 = (String) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                this.c.setValue(it8);
                this.b.invoke(it8);
                break;
            case 11:
                s it9 = (s) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                if (!it9.a()) {
                    this.b.invoke((String) this.c.getValue());
                }
                break;
            case 12:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                this.b.invoke((String) this.c.getValue());
                break;
            case 13:
                s it10 = (s) obj;
                Intrinsics.checkNotNullParameter(it10, "it");
                if (!it10.a()) {
                    this.b.invoke((String) this.c.getValue());
                }
                break;
            case 14:
                Long l = (Long) obj;
                l.longValue();
                this.c.setValue(l);
                this.b.invoke(l);
                break;
            case 15:
                String it11 = (String) obj;
                Intrinsics.checkNotNullParameter(it11, "it");
                this.c.setValue(it11);
                this.b.invoke(it11);
                break;
            default:
                String it12 = (String) obj;
                Intrinsics.checkNotNullParameter(it12, "it");
                this.c.setValue(it12);
                this.b.invoke(it12);
                break;
        }
        return Unit.a;
    }
}
