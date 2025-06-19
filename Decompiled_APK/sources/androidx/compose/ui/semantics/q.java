package androidx.compose.ui.semantics;

import java.util.ArrayList;
import java.util.List;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class q extends kotlin.jvm.internal.r implements Function2 {
    public static final q b = new q(2, 0);
    public static final q c = new q(2, 1);
    public static final q d = new q(2, 2);
    public static final q e = new q(2, 3);
    public static final q f = new q(2, 4);
    public static final q g = new q(2, 5);
    public static final q h = new q(2, 6);
    public static final q i = new q(2, 7);
    public static final q j = new q(2, 8);
    public static final q k = new q(2, 9);
    public static final q l = new q(2, 10);
    public static final q m = new q(2, 11);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ q(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        String str;
        InterfaceC4938g interfaceC4938g;
        switch (this.a) {
            case 0:
                List list = (List) obj;
                List list2 = (List) obj2;
                if (list == null) {
                    return list2;
                }
                ArrayList arrayListY0 = CollectionsKt.y0(list);
                arrayListY0.addAll(list2);
                return arrayListY0;
            case 1:
                return (Unit) obj;
            case 2:
                throw new IllegalStateException("merge function called on unmergeable property IsDialog. A dialog should not be a child of a clickable/focusable node.");
            case 3:
                throw new IllegalStateException("merge function called on unmergeable property IsPopup. A popup should not be a child of a clickable/focusable node.");
            case 4:
                throw new IllegalStateException("merge function called on unmergeable property PaneTitle.");
            case 5:
                h hVar = (h) obj;
                int i2 = ((h) obj2).a;
                return hVar;
            case 6:
                return (String) obj;
            case 7:
                List list3 = (List) obj;
                List list4 = (List) obj2;
                if (list3 == null) {
                    return list4;
                }
                ArrayList arrayListY02 = CollectionsKt.y0(list3);
                arrayListY02.addAll(list4);
                return arrayListY02;
            case 8:
                Float f2 = (Float) obj;
                ((Number) obj2).floatValue();
                return f2;
            case 9:
                Boolean bool = (Boolean) obj;
                ((Boolean) obj2).booleanValue();
                return bool;
            case 10:
                a aVar = (a) obj;
                a aVar2 = (a) obj2;
                if (aVar == null || (str = aVar.a) == null) {
                    str = aVar2.a;
                }
                if (aVar == null || (interfaceC4938g = aVar.b) == null) {
                    interfaceC4938g = aVar2.b;
                }
                return new a(str, interfaceC4938g);
            default:
                return obj == null ? obj2 : obj;
        }
    }
}
