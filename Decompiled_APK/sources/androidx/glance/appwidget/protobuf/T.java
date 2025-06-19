package androidx.glance.appwidget.protobuf;

/* loaded from: classes.dex */
public final class T extends Q {
    @Override // androidx.glance.appwidget.protobuf.Q
    public final S a(Object obj) {
        AbstractC1206s abstractC1206s = (AbstractC1206s) obj;
        S s = abstractC1206s.unknownFields;
        if (s != S.f) {
            return s;
        }
        S s2 = new S(0, new int[8], new Object[8], true);
        abstractC1206s.unknownFields = s2;
        return s2;
    }
}
