const mongoose = require("mongoose");
const ObjectId = mongoose.Schema.Types.ObjectId;

const eventSchema = new mongoose.Schema(
    {
        creator: {
            type: ObjectId
        },
        title: {
            type: String,
            required: true,
            trim: true,
        },
        description: {
            type: String,
            trim: true,
        },
        eventDate: {
            type: String,
            required: true,
            trim: true,
        },
        invitees: [
            {
                invitee: { type: ObjectId, ref: "User", required: true },
                timings: {
                    type: String,
                    required: true,
                },
            },
        ],
    },

    { timestamps: true }
);

module.exports = mongoose.model("Eventssss", eventSchema);