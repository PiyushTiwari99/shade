const EventModel = require("../models/eventModle");
const validator = require("../validation/valid");

const addsEvent = async (req, res) => {
    try {
        if (!validator.isValidRequestBody(req.body))
            return res.status(400).json({
                status: false,
                msg: "invalid request parameters ,please provide event details",
            });

        let { creator, title, description, eventDate } = req.body;
        let { invitee, timings } = req.body.invitees[0];

        if (!validator.isValid(creator) && !validator.isValidObjectId(creator))
            return res
                .status(400)
                .json({ status: false, msg: "please provide creator id" });

        if (!validator.isValid(title))
            return res
                .status(400)
                .json({ status: false, msg: "please provide title" });

        if (!validator.isValid(description))
            return res
                .status(400)
                .json({ status: false, msg: "please provide description" });

        if (!validator.isValid(eventDate))
            return res
                .status(400)
                .json({ status: false, msg: "please provide event date" });

        if (!validator.isValidObjectId(invitee) && !validator.isValid(invitee))
            return res
                .status(400)
                .json({ status: false, msg: "please provide valid invite id" });

        if (!validator.isValid(timings))
            return res
                .status(400)
                .json({ status: false, msg: "please provide timings" });

        let newEvent = await EventModel.create(req.body);
        return res
            .status(201)
            .json({ status: true, msg: "event added successfully", data: newEvent });
    } catch (err) {
        return res.status(500).json({ status: false, msg: err.message });
    }
};

//

const invites = async (req, res) => {
    try {
        let eventId = req.params.id;
        let eventFinder = await EventModel.findOne({ eventId });

        if (!eventFinder)
            return res
                .status(400)
                .json({ status: false, msg: "no such event is present" });

        let { invitee, timings } = req.body;

        if (!validator.isValidObjectId(invitee) && !validator.isValid(invitee))
            return res
                .status(400)
                .json({ status: false, msg: "please provide valid invite id" });

        if (!validator.isValid(timings))
            return res
                .status(400)
                .json({ status: false, msg: "please provide timings" });

        let invitation = await EventModel.findOneAndUpdate(
            { _id: req.params.id },
            { $push: { invitees: { invitee: invitee, timings: timings } } },
            { new: true }
        );

        return res.status(200).json({ status: true, data: invitation });
    } catch (err) {
        return res.status(500).json({ status: false, msg: err.message });
    }
};

//

const eventssss = async (req, res) => {
    try {
        let { date, name, sort } = req.query;

        if (date) {
            let dateFilter = await EventModel.findOne({ eventDate: date });

            if (dateFilter.length !== 0) {
                return res.status(200).json({
                    status: true,
                    msg: "Successfully found",
                    data: { dateFilter },
                });
            } else {
                return res
                    .status(400)
                    .json({ status: false, msg: `No event with ${date} found` });
            }
        }
        if (name) {
            let findName = await EventModel.find({
                title: { $regex: name, $options: "i" },
            });

            if (findName.length != 0) {
                return res.status(200).json({
                    status: true,
                    msg: "Successfully found",
                    data: { findName },
                });
            } else {
                return res
                    .status(400)
                    .json({ status: false, msg: `No event with ${name} found` });
            }
        }

        if (sort) {
            let findSort = await EventModel.find({}).sort({ title: sort });

            if (findSort.length != 0) {
                return res.status(200).json({
                    status: true,
                    msg: "Successfully found",
                    data: { findSort },
                });
            } else {
                return res
                    .status(400)
                    .json({ status: false, msg: `No products of size ${Size} found` });
            }
        }
    } catch (err) {
        return res.status(500).json({ status: false, msg: err.message });
    }
};

//

const updateEventss = async (req, res) => {
    try {
        if (!validator.isValidObjectId(req.params.id))
            return res
                .status(400)
                .json({ status: false, message: "Invalid event id" });

        let findEvent = await EventModel.findOne({ _id: req.params.id });

        if (!findEvent)
            return res
                .status(400)
                .json({ status: false, message: "event does not exits" });

        let { creator, title, description, eventDate } = req.body;
        let { invitee, timings } = req.body.invitees[0];

        if (!validator.isValidRequestBody(req.body))
            return res.status(400).json({
                status: false,
                message: "Invalid request parameters. Please provide event details.",
            });

        if (!validator.isValid(creator) && !validator.isValidObjectId(creator))
            return res
                .status(400)
                .json({ status: false, msg: "please provide creator id" });

        if (!validator.isValid(title))
            return res
                .status(400)
                .json({ status: false, msg: "please provide title" });

        if (!validator.isValid(description))
            return res
                .status(400)
                .json({ status: false, msg: "please provide description" });

        if (!validator.isValid(eventDate))
            return res
                .status(400)
                .json({ status: false, msg: "please provide event date" });

        if (!validator.isValidObjectId(invitee) && !validator.isValid(invitee))
            return res
                .status(400)
                .json({ status: false, msg: "please provide valid invite id" });

        if (!validator.isValid(timings))
            return res
                .status(400)
                .json({ status: false, msg: "please provide timings" });

        let data = await EventModel.findOneAndUpdate(
            { _id: req.params.id },
            { $set: req.body },
            { new: true }
        );

        return res.status(200).json({
            status: true,
            message: `successfully updated`,
            data: data,
        });
    } catch (err) {
        return res.status(500).json({ status: false, msg: err.message });
    }
};

//

const detailssss = async (req, res) => {
    try {
        let eventId = req.params.id;
        let getEvents = await EventModel.findOne({ eventId });

        if (!getEvents)
            return res.status(400).json({ status: false, msg: "no events found" });

        return res
            .status(200)
            .json({ status: false, msg: "events listed", data: getEvents });
    } catch (err) {
        return res.status(500).json({ status: false, msg: err.message });
    }
};

module.exports = { addsEvent, invites, eventssss, updateEventss, detailssss };
