package com.quizlet.login.signup.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.LearnSettingsGradingUpdateData;
import com.skydoves.balloon.compose.BalloonWindow;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC0773a0 b;

    public /* synthetic */ a(InterfaceC0773a0 interfaceC0773a0, int i) {
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
                Boolean bool = (Boolean) obj;
                bool.booleanValue();
                this.b.setValue(bool);
                break;
            case 3:
                String it4 = (String) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                this.b.setValue(it4);
                break;
            case 4:
                String it5 = (String) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                this.b.setValue(it5);
                break;
            case 5:
                Boolean bool2 = (Boolean) obj;
                bool2.booleanValue();
                this.b.setValue(bool2);
                break;
            case 6:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                InterfaceC0773a0 interfaceC0773a0 = this.b;
                interfaceC0773a0.setValue(LearnSettingsUpdateData.a((LearnSettingsUpdateData) interfaceC0773a0.getValue(), zBooleanValue, false, false, false, false, false, false, false, false, null, 4094));
                break;
            case 7:
                boolean zBooleanValue2 = ((Boolean) obj).booleanValue();
                InterfaceC0773a0 interfaceC0773a02 = this.b;
                interfaceC0773a02.setValue(LearnSettingsUpdateData.a((LearnSettingsUpdateData) interfaceC0773a02.getValue(), false, false, false, false, false, false, zBooleanValue2, false, false, null, 4031));
                break;
            case 8:
                boolean zBooleanValue3 = ((Boolean) obj).booleanValue();
                InterfaceC0773a0 interfaceC0773a03 = this.b;
                interfaceC0773a03.setValue(LearnSettingsUpdateData.a((LearnSettingsUpdateData) interfaceC0773a03.getValue(), false, false, false, false, false, false, false, zBooleanValue3, false, null, 3967));
                break;
            case 9:
                boolean zBooleanValue4 = ((Boolean) obj).booleanValue();
                InterfaceC0773a0 interfaceC0773a04 = this.b;
                interfaceC0773a04.setValue(LearnSettingsUpdateData.a((LearnSettingsUpdateData) interfaceC0773a04.getValue(), false, false, false, false, false, false, false, false, zBooleanValue4, null, 3839));
                break;
            case 10:
                WrittenQuestionGradingOption it6 = (WrittenQuestionGradingOption) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                InterfaceC0773a0 interfaceC0773a05 = this.b;
                interfaceC0773a05.setValue(LearnSettingsUpdateData.a((LearnSettingsUpdateData) interfaceC0773a05.getValue(), false, false, false, false, false, false, false, false, false, it6, 2047));
                break;
            case 11:
                boolean zBooleanValue5 = ((Boolean) obj).booleanValue();
                InterfaceC0773a0 interfaceC0773a06 = this.b;
                interfaceC0773a06.setValue(LearnSettingsUpdateData.a((LearnSettingsUpdateData) interfaceC0773a06.getValue(), false, zBooleanValue5, false, false, false, false, false, false, false, null, 4093));
                break;
            case 12:
                boolean zBooleanValue6 = ((Boolean) obj).booleanValue();
                InterfaceC0773a0 interfaceC0773a07 = this.b;
                interfaceC0773a07.setValue(LearnSettingsUpdateData.a((LearnSettingsUpdateData) interfaceC0773a07.getValue(), false, false, zBooleanValue6, false, false, false, false, false, false, null, 4091));
                break;
            case 13:
                boolean zBooleanValue7 = ((Boolean) obj).booleanValue();
                InterfaceC0773a0 interfaceC0773a08 = this.b;
                interfaceC0773a08.setValue(LearnSettingsUpdateData.a((LearnSettingsUpdateData) interfaceC0773a08.getValue(), false, false, false, zBooleanValue7, false, false, false, false, false, null, 4087));
                break;
            case 14:
                boolean zBooleanValue8 = ((Boolean) obj).booleanValue();
                InterfaceC0773a0 interfaceC0773a09 = this.b;
                interfaceC0773a09.setValue(LearnSettingsUpdateData.a((LearnSettingsUpdateData) interfaceC0773a09.getValue(), false, false, false, false, zBooleanValue8, false, false, false, false, null, 4079));
                break;
            case 15:
                boolean zBooleanValue9 = ((Boolean) obj).booleanValue();
                InterfaceC0773a0 interfaceC0773a010 = this.b;
                interfaceC0773a010.setValue(LearnSettingsUpdateData.a((LearnSettingsUpdateData) interfaceC0773a010.getValue(), false, false, false, false, false, zBooleanValue9, false, false, false, null, 4063));
                break;
            case 16:
                LearnSettingsUpdateData it7 = (LearnSettingsUpdateData) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                this.b.setValue(it7);
                break;
            case 17:
                boolean zBooleanValue10 = ((Boolean) obj).booleanValue();
                InterfaceC0773a0 interfaceC0773a011 = this.b;
                interfaceC0773a011.setValue(LearnSettingsGradingUpdateData.a((LearnSettingsGradingUpdateData) interfaceC0773a011.getValue(), zBooleanValue10, false, false, 6));
                break;
            case 18:
                boolean zBooleanValue11 = ((Boolean) obj).booleanValue();
                InterfaceC0773a0 interfaceC0773a012 = this.b;
                interfaceC0773a012.setValue(LearnSettingsGradingUpdateData.a((LearnSettingsGradingUpdateData) interfaceC0773a012.getValue(), false, zBooleanValue11, false, 5));
                break;
            case 19:
                boolean zBooleanValue12 = ((Boolean) obj).booleanValue();
                InterfaceC0773a0 interfaceC0773a013 = this.b;
                interfaceC0773a013.setValue(LearnSettingsGradingUpdateData.a((LearnSettingsGradingUpdateData) interfaceC0773a013.getValue(), false, false, zBooleanValue12, 3));
                break;
            default:
                BalloonWindow it8 = (BalloonWindow) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                this.b.setValue(it8);
                break;
        }
        return Unit.a;
    }
}
