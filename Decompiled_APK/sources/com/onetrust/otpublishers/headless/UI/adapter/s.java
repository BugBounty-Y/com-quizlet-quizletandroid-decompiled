package com.onetrust.otpublishers.headless.UI.adapter;

import androidx.recyclerview.widget.AbstractC1358c;
import com.quizlet.data.model.CreatedFolderWithCreator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class s extends AbstractC1358c {
    public final /* synthetic */ int d;

    public /* synthetic */ s(int i) {
        this.d = i;
    }

    @Override // androidx.recyclerview.widget.AbstractC1358c
    public final boolean a(Object obj, Object obj2) {
        switch (this.d) {
            case 0:
                com.onetrust.otpublishers.headless.UI.DataModels.g oldItem = (com.onetrust.otpublishers.headless.UI.DataModels.g) obj;
                com.onetrust.otpublishers.headless.UI.DataModels.g newItem = (com.onetrust.otpublishers.headless.UI.DataModels.g) obj2;
                Intrinsics.checkNotNullParameter(oldItem, "oldItem");
                Intrinsics.checkNotNullParameter(newItem, "newItem");
                return Intrinsics.b(oldItem.b, newItem.b) && oldItem.d == newItem.d;
            case 1:
                com.onetrust.otpublishers.headless.UI.DataModels.j oldItem2 = (com.onetrust.otpublishers.headless.UI.DataModels.j) obj;
                com.onetrust.otpublishers.headless.UI.DataModels.j newItem2 = (com.onetrust.otpublishers.headless.UI.DataModels.j) obj2;
                Intrinsics.checkNotNullParameter(oldItem2, "oldItem");
                Intrinsics.checkNotNullParameter(newItem2, "newItem");
                return Intrinsics.b(oldItem2.b, newItem2.b) && oldItem2.c == newItem2.c;
            case 2:
                com.quizlet.baserecyclerview.a oldItem3 = (com.quizlet.baserecyclerview.a) obj;
                com.quizlet.baserecyclerview.a newItem3 = (com.quizlet.baserecyclerview.a) obj2;
                Intrinsics.checkNotNullParameter(oldItem3, "oldItem");
                Intrinsics.checkNotNullParameter(newItem3, "newItem");
                return oldItem3.equals(newItem3);
            case 3:
                CreatedFolderWithCreator oldItem4 = (CreatedFolderWithCreator) obj;
                CreatedFolderWithCreator newItem4 = (CreatedFolderWithCreator) obj2;
                Intrinsics.checkNotNullParameter(oldItem4, "oldItem");
                Intrinsics.checkNotNullParameter(newItem4, "newItem");
                return oldItem4.equals(newItem4);
            case 4:
                com.quizlet.quizletandroid.ui.group.classcontent.models.a oldItem5 = (com.quizlet.quizletandroid.ui.group.classcontent.models.a) obj;
                com.quizlet.quizletandroid.ui.group.classcontent.models.a newItem5 = (com.quizlet.quizletandroid.ui.group.classcontent.models.a) obj2;
                Intrinsics.checkNotNullParameter(oldItem5, "oldItem");
                Intrinsics.checkNotNullParameter(newItem5, "newItem");
                return oldItem5.equals(newItem5);
            case 5:
                com.quizlet.quizletandroid.ui.joincontenttofolder.models.c oldItem6 = (com.quizlet.quizletandroid.ui.joincontenttofolder.models.c) obj;
                com.quizlet.quizletandroid.ui.joincontenttofolder.models.c newItem6 = (com.quizlet.quizletandroid.ui.joincontenttofolder.models.c) obj2;
                Intrinsics.checkNotNullParameter(oldItem6, "oldItem");
                Intrinsics.checkNotNullParameter(newItem6, "newItem");
                if ((oldItem6 instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.models.b) && (newItem6 instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.models.b)) {
                    return ((com.quizlet.quizletandroid.ui.joincontenttofolder.models.b) oldItem6).equals((com.quizlet.quizletandroid.ui.joincontenttofolder.models.b) newItem6);
                }
                return false;
            default:
                com.quizlet.uicommon.ui.common.overflowmenu.f oldItem7 = (com.quizlet.uicommon.ui.common.overflowmenu.f) obj;
                com.quizlet.uicommon.ui.common.overflowmenu.f newItem7 = (com.quizlet.uicommon.ui.common.overflowmenu.f) obj2;
                Intrinsics.checkNotNullParameter(oldItem7, "oldItem");
                Intrinsics.checkNotNullParameter(newItem7, "newItem");
                return oldItem7.equals(newItem7);
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1358c
    public final boolean b(Object obj, Object obj2) {
        switch (this.d) {
            case 0:
                com.onetrust.otpublishers.headless.UI.DataModels.g oldItem = (com.onetrust.otpublishers.headless.UI.DataModels.g) obj;
                com.onetrust.otpublishers.headless.UI.DataModels.g newItem = (com.onetrust.otpublishers.headless.UI.DataModels.g) obj2;
                Intrinsics.checkNotNullParameter(oldItem, "oldItem");
                Intrinsics.checkNotNullParameter(newItem, "newItem");
                return Intrinsics.b(oldItem.a, newItem.a);
            case 1:
                com.onetrust.otpublishers.headless.UI.DataModels.j oldItem2 = (com.onetrust.otpublishers.headless.UI.DataModels.j) obj;
                com.onetrust.otpublishers.headless.UI.DataModels.j newItem2 = (com.onetrust.otpublishers.headless.UI.DataModels.j) obj2;
                Intrinsics.checkNotNullParameter(oldItem2, "oldItem");
                Intrinsics.checkNotNullParameter(newItem2, "newItem");
                return Intrinsics.b(oldItem2.a, newItem2.a);
            case 2:
                com.quizlet.baserecyclerview.a oldItem3 = (com.quizlet.baserecyclerview.a) obj;
                com.quizlet.baserecyclerview.a newItem3 = (com.quizlet.baserecyclerview.a) obj2;
                Intrinsics.checkNotNullParameter(oldItem3, "oldItem");
                Intrinsics.checkNotNullParameter(newItem3, "newItem");
                return (oldItem3.getClass() == newItem3.getClass()) && Intrinsics.b(oldItem3.getItemId(), newItem3.getItemId());
            case 3:
                CreatedFolderWithCreator oldItem4 = (CreatedFolderWithCreator) obj;
                CreatedFolderWithCreator newItem4 = (CreatedFolderWithCreator) obj2;
                Intrinsics.checkNotNullParameter(oldItem4, "oldItem");
                Intrinsics.checkNotNullParameter(newItem4, "newItem");
                return oldItem4.a.a() == newItem4.a.a();
            case 4:
                com.quizlet.quizletandroid.ui.group.classcontent.models.a oldItem5 = (com.quizlet.quizletandroid.ui.group.classcontent.models.a) obj;
                com.quizlet.quizletandroid.ui.group.classcontent.models.a newItem5 = (com.quizlet.quizletandroid.ui.group.classcontent.models.a) obj2;
                Intrinsics.checkNotNullParameter(oldItem5, "oldItem");
                Intrinsics.checkNotNullParameter(newItem5, "newItem");
                return oldItem5.b() == newItem5.b();
            case 5:
                com.quizlet.quizletandroid.ui.joincontenttofolder.models.c oldItem6 = (com.quizlet.quizletandroid.ui.joincontenttofolder.models.c) obj;
                com.quizlet.quizletandroid.ui.joincontenttofolder.models.c newItem6 = (com.quizlet.quizletandroid.ui.joincontenttofolder.models.c) obj2;
                Intrinsics.checkNotNullParameter(oldItem6, "oldItem");
                Intrinsics.checkNotNullParameter(newItem6, "newItem");
                return ((oldItem6 instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.models.b) && (newItem6 instanceof com.quizlet.quizletandroid.ui.joincontenttofolder.models.b) && ((com.quizlet.quizletandroid.ui.joincontenttofolder.models.b) oldItem6).a.c() != ((com.quizlet.quizletandroid.ui.joincontenttofolder.models.b) newItem6).a.c()) ? false : true;
            default:
                com.quizlet.uicommon.ui.common.overflowmenu.f oldItem7 = (com.quizlet.uicommon.ui.common.overflowmenu.f) obj;
                com.quizlet.uicommon.ui.common.overflowmenu.f newItem7 = (com.quizlet.uicommon.ui.common.overflowmenu.f) obj2;
                Intrinsics.checkNotNullParameter(oldItem7, "oldItem");
                Intrinsics.checkNotNullParameter(newItem7, "newItem");
                Intrinsics.checkNotNullParameter(oldItem7, "oldItem");
                Intrinsics.checkNotNullParameter(newItem7, "newItem");
                return oldItem7.equals(newItem7);
        }
    }
}
