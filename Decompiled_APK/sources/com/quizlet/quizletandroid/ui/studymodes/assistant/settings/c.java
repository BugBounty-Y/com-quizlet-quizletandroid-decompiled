package com.quizlet.quizletandroid.ui.studymodes.assistant.settings;

import androidx.compose.animation.core.P;
import androidx.compose.runtime.H;
import androidx.lifecycle.A;
import androidx.lifecycle.J;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ J b;
    public final /* synthetic */ com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a c;

    public /* synthetic */ c(J j, com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar, int i) {
        this.a = i;
        this.b = j;
        this.c = aVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        H DisposableEffect = (H) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(DisposableEffect, "$this$DisposableEffect");
                final com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar = this.c;
                final int i = 0;
                androidx.lifecycle.H h = new androidx.lifecycle.H() { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.d
                    @Override // androidx.lifecycle.H
                    public final void d(J j, A event) {
                        switch (i) {
                            case 0:
                                Intrinsics.checkNotNullParameter(j, "<unused var>");
                                Intrinsics.checkNotNullParameter(event, "event");
                                int i2 = h.a[event.ordinal()];
                                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar2 = aVar;
                                if (i2 == 1) {
                                    ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) aVar2).D();
                                    break;
                                } else if (i2 == 2) {
                                    ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) aVar2).E();
                                    break;
                                }
                                break;
                            default:
                                Intrinsics.checkNotNullParameter(j, "<unused var>");
                                Intrinsics.checkNotNullParameter(event, "event");
                                int i3 = s.a[event.ordinal()];
                                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar3 = aVar;
                                if (i3 == 1) {
                                    ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) aVar3).D();
                                    break;
                                } else if (i3 == 2) {
                                    ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) aVar3).E();
                                    break;
                                }
                                break;
                        }
                    }
                };
                J j = this.b;
                j.getLifecycle().a(h);
                return new P(20, j, h);
            default:
                Intrinsics.checkNotNullParameter(DisposableEffect, "$this$DisposableEffect");
                final com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar2 = this.c;
                final int i2 = 1;
                androidx.lifecycle.H h2 = new androidx.lifecycle.H() { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.settings.d
                    @Override // androidx.lifecycle.H
                    public final void d(J j2, A event) {
                        switch (i2) {
                            case 0:
                                Intrinsics.checkNotNullParameter(j2, "<unused var>");
                                Intrinsics.checkNotNullParameter(event, "event");
                                int i22 = h.a[event.ordinal()];
                                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar22 = aVar2;
                                if (i22 == 1) {
                                    ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) aVar22).D();
                                    break;
                                } else if (i22 == 2) {
                                    ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) aVar22).E();
                                    break;
                                }
                                break;
                            default:
                                Intrinsics.checkNotNullParameter(j2, "<unused var>");
                                Intrinsics.checkNotNullParameter(event, "event");
                                int i3 = s.a[event.ordinal()];
                                com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.a aVar3 = aVar2;
                                if (i3 == 1) {
                                    ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) aVar3).D();
                                    break;
                                } else if (i3 == 2) {
                                    ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.viewmodel.i) aVar3).E();
                                    break;
                                }
                                break;
                        }
                    }
                };
                J j2 = this.b;
                j2.getLifecycle().a(h2);
                return new P(21, j2, h2);
        }
    }
}
