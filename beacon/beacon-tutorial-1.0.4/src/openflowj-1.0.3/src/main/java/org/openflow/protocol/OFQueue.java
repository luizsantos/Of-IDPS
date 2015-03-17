package org.openflow.protocol;

public enum OFQueue {
    OFPQ_ALL                (0xffffffff);

    protected int queueId;

    OFQueue(int queueId) {
        this.queueId = queueId;
    }

    /**
     * @return the queueId
     */
    public int getQueueId() {
        return queueId;
    }
}
